import {
    Injectable,
    UnauthorizedException,
    NotFoundException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { UsersService } from '../users/users.service';
import { RefreshToken } from './entities/refresh-token.entity';
import { User } from '../users/entities/user.entity';
import {
    generateChallengeMessage,
    verifyStellarSignature,
    isChallengeExpired,
    extractTimestampFromChallenge,
} from './utils/signature';
import {
    LoginDto,
    TokenResponseDto,
    UserResponseDto,
    ChallengeResponseDto,
} from './dto/auth.dto';
import * as crypto from 'crypto';

@Injectable()
export class AuthService {
    constructor(
        private readonly jwtService: JwtService,
        private readonly configService: ConfigService,
        private readonly usersService: UsersService,
        @InjectRepository(RefreshToken)
        private readonly refreshTokenRepository: Repository<RefreshToken>,
    ) { }

    /**
     * Generate a challenge message for wallet signature
     */
    async generateChallenge(stellarAddress: string): Promise<ChallengeResponseDto> {
        const timestamp = Date.now();
        const challenge = generateChallengeMessage(stellarAddress, timestamp);

        const expirationMinutes = parseInt(
            this.configService.get<string>('AUTH_CHALLENGE_EXPIRATION', '5'),
            10,
        );

        const expiresAt = new Date(timestamp + expirationMinutes * 60 * 1000);

        return {
            challenge,
            expiresAt,
        };
    }

    /**
     * Verify signature and login user
     */
    async verifySignatureAndLogin(loginDto: LoginDto): Promise<TokenResponseDto> {
        const { stellarAddress, signature, challenge } = loginDto;

        const timestamp = extractTimestampFromChallenge(challenge);
        const expirationMinutes = parseInt(
            this.configService.get<string>('AUTH_CHALLENGE_EXPIRATION', '5'),
            10,
        );

        if (isChallengeExpired(timestamp, expirationMinutes)) {
            throw new UnauthorizedException('Challenge has expired');
        }

        verifyStellarSignature(stellarAddress, signature, challenge);

        let user = await this.usersService.findByAddress(stellarAddress);
        if (!user) {
            user = await this.usersService.create(stellarAddress);
        }

        const tokens = await this.generateTokens(user);

        return {
            ...tokens,
            user: this.mapUserToResponse(user),
        };
    }

    /**
     * Generate access and refresh tokens
     */
    async generateTokens(user: User): Promise<{
        accessToken: string;
        refreshToken: string;
    }> {
        const payload = {
            sub: user.id,
            stellarAddress: user.stellarAddress,
            role: user.role,
        };

        const accessToken = this.jwtService.sign(payload, {
            expiresIn: this.configService.get<string>(
                'JWT_ACCESS_TOKEN_EXPIRATION',
                '15m',
            ),
        } as any);

        const refreshTokenValue = crypto.randomBytes(32).toString('hex');
        const refreshTokenExpiration = this.configService.get<string>(
            'JWT_REFRESH_TOKEN_EXPIRATION',
            '7d',
        );

        const expirationMs = this.parseExpirationToMs(refreshTokenExpiration);
        const expiresAt = new Date(Date.now() + expirationMs);

        const refreshToken = this.refreshTokenRepository.create({
            token: refreshTokenValue,
            userId: user.id,
            expiresAt,
        });

        await this.refreshTokenRepository.save(refreshToken);

        return {
            accessToken,
            refreshToken: refreshTokenValue,
        };
    }

    /**
     * Refresh access token using refresh token
     */
    async refreshTokens(refreshTokenValue: string): Promise<TokenResponseDto> {
        const refreshToken = await this.refreshTokenRepository.findOne({
            where: { token: refreshTokenValue },
            relations: ['user'],
        });

        if (!refreshToken) {
            throw new UnauthorizedException('Invalid refresh token');
        }

        if (refreshToken.isRevoked) {
            throw new UnauthorizedException('Refresh token has been revoked');
        }

        if (new Date() > refreshToken.expiresAt) {
            throw new UnauthorizedException('Refresh token has expired');
        }

        refreshToken.isRevoked = true;
        await this.refreshTokenRepository.save(refreshToken);

        const tokens = await this.generateTokens(refreshToken.user);

        return {
            ...tokens,
            user: this.mapUserToResponse(refreshToken.user),
        };
    }

    /**
     * Revoke a specific refresh token or all user tokens
     */
    async revokeToken(userId: string, tokenId?: string): Promise<void> {
        if (tokenId) {
            const token = await this.refreshTokenRepository.findOne({
                where: { id: tokenId, userId },
            });

            if (!token) {
                throw new NotFoundException('Token not found');
            }

            token.isRevoked = true;
            await this.refreshTokenRepository.save(token);
        } else {
            await this.refreshTokenRepository.update(
                { userId, isRevoked: false },
                { isRevoked: true },
            );
        }
    }

    /**
     * Validate user for JWT strategy
     */
    async validateUser(userId: string): Promise<User> {
        const user = await this.usersService.findById(userId);
        if (!user) {
            throw new UnauthorizedException('User not found');
        }
        return user;
    }

    /**
     * Map User entity to response DTO
     */
    private mapUserToResponse(user: User): UserResponseDto {
        return {
            id: user.id,
            stellarAddress: user.stellarAddress,
            username: user.username,
            email: user.email,
            role: user.role,
            xp: user.xp,
            level: user.level,
        };
    }

    /**
     * Parse expiration string (e.g., "7d", "15m") to milliseconds
     */
    private parseExpirationToMs(expiration: string): number {
        const match = expiration.match(/^(\d+)([smhd])$/);
        if (!match) {
            throw new Error('Invalid expiration format');
        }

        const value = parseInt(match[1], 10);
        const unit = match[2];

        const multipliers = {
            s: 1000,
            m: 60 * 1000,
            h: 60 * 60 * 1000,
            d: 24 * 60 * 60 * 1000,
        };

        return value * multipliers[unit];
    }
}

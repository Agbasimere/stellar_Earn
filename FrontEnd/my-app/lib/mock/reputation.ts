import type { UserReputation, Badge } from '@/lib/types/reputation';

export const mockUserReputation: UserReputation = {
  userId: 'user-123',
  level: 12,
  xp: 4500,
  reputation: 1250,
  questsCompleted: 45,
  badges: ['first-quest', 'quest-master', 'early-adopter'],
  updatedAt: new Date().toISOString(),
};

export const mockBadges: Badge[] = [
  {
    id: 'first-quest',
    name: 'First Quest',
    description: 'Complete your first quest',
    icon: '🎯',
    requirement: 'Complete 1 quest',
    rarity: 'common',
    unlockedAt: new Date('2024-01-15').toISOString(),
  },
  {
    id: 'quest-master',
    name: 'Quest Master',
    description: 'Complete 50 quests',
    icon: '🏆',
    requirement: 'Complete 50 quests',
    rarity: 'rare',
    unlockedAt: new Date('2024-03-20').toISOString(),
  },
  {
    id: 'early-adopter',
    name: 'Early Adopter',
    description: 'Join during the beta phase',
    icon: '⭐',
    requirement: 'Join before public launch',
    rarity: 'epic',
    unlockedAt: new Date('2024-01-01').toISOString(),
  },
  {
    id: 'speed-demon',
    name: 'Speed Demon',
    description: 'Complete 10 quests in one day',
    icon: '⚡',
    requirement: 'Complete 10 quests in 24 hours',
    rarity: 'rare',
  },
  {
    id: 'perfectionist',
    name: 'Perfectionist',
    description: 'Get 100% approval rate on 20 submissions',
    icon: '✨',
    requirement: '100% approval on 20 submissions',
    rarity: 'epic',
  },
  {
    id: 'legend',
    name: 'Legend',
    description: 'Reach level 100',
    icon: '👑',
    requirement: 'Reach level 100',
    rarity: 'legendary',
  },
  {
    id: 'social-butterfly',
    name: 'Social Butterfly',
    description: 'Refer 10 friends',
    icon: '🦋',
    requirement: 'Refer 10 users',
    rarity: 'common',
  },
  {
    id: 'night-owl',
    name: 'Night Owl',
    description: 'Complete quests between midnight and 4 AM',
    icon: '🦉',
    requirement: 'Complete 5 quests at night',
    rarity: 'rare',
  },
  {
    id: 'weekend-warrior',
    name: 'Weekend Warrior',
    description: 'Complete 20 quests on weekends',
    icon: '🎮',
    requirement: 'Complete 20 weekend quests',
    rarity: 'common',
  },
  {
    id: 'centurion',
    name: 'Centurion',
    description: 'Complete 100 quests',
    icon: '💯',
    requirement: 'Complete 100 quests',
    rarity: 'legendary',
  },
];

export function getMockReputation(userId?: string): UserReputation {
  return mockUserReputation;
}

export function getMockBadges(): Badge[] {
  return mockBadges;
}

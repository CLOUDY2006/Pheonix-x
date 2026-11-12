import { Activity, BarChart3, Bot, CheckCheck, FileText, House, LayoutGrid, LifeBuoy, ListChecks, Search, Server, ShieldCheck, Siren, SlidersHorizontal, Waypoints, type LucideIcon } from 'lucide-react';

export type NavItem = [key: string, label: string, icon: LucideIcon, hint?: string];

export const MAIN: NavItem[] = [
  ['command', 'Home', House, 'Are we safe?'],
  ['approvals', 'Needs you', CheckCheck, 'Decisions, one tap'],
  ['activity', 'Activity', ListChecks, 'What happened'],
  ['settings', 'Settings', SlidersHorizontal, 'How much AI does'],
  ['advanced', 'More tools', LayoutGrid, 'For experts'],
];

export const ADV: NavItem[] = [
  ['live', 'Live monitor', Activity, 'Every event as it happens'],
  ['graph', 'Attack map', Waypoints, 'See how an attack moved'],
  ['recovery', 'Recovery', LifeBuoy, 'Backups and restore progress'],
  ['agents', 'AI helpers', Bot, 'Who does what, and what they say'],
  ['intel', 'Threat lookup', Search, 'Check an address, site or file'],
  ['assets', 'Assets', Server, 'Accounts, computers, keys and data'],
  ['analytics', 'Trends', BarChart3, 'Charts of what came in and what was caught'],
  ['audit', 'Audit log', FileText, 'A tamper-proof record of everything'],
  ['response', 'Safety rules', ShieldCheck, 'What Phoenix X may and may not do'],
];

export const CLASSIC: { label: string; hint: string; href: string }[] = [
  { label: 'Connect a platform', hint: 'Keys, log shippers and read-only collectors', href: '/classic/#/connect' },
  { label: 'Chat and alerts', hint: 'Telegram, Slack, Discord and email', href: '/classic/#/channels' },
  { label: 'Application resilience', hint: 'Dependency map, blast radius, rehearsals, recovery plans', href: '/classic/#/resilience' },
  { label: 'Users, keys and backups', hint: 'Team accounts, two-factor and key rotation', href: '/classic/#/settings' },
];

export const ALL_NAV: NavItem[] = [...MAIN, ...ADV, ['incidents', 'Incident', Siren]];

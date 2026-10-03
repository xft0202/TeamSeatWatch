import { MantineProvider, Container, Group, Text } from '@mantine/core';
import { createRoot } from 'react-dom/client';
import '@fontsource/dm-sans/400.css';
import '@fontsource/dm-sans/600.css';
import { appTheme } from '../rebuild/shared/theme';
import './public.css';
import RedeemPage from './RedeemPage';

const root = document.getElementById('root');
if (!root) throw new Error('Public root element is missing');
createRoot(root).render(<MantineProvider theme={appTheme} defaultColorScheme="light"><div className="public-shell"><header className="public-header"><Container size={1280}><Group h={56}><Text fw={600}>Apophis-TeamSeatWatch</Text></Group></Container></header><main><RedeemPage /></main></div></MantineProvider>);

// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
	integrations: [
		starlight({
			title: 'Hackatorium',
			logo: {
				dark: './src/assets/LogoSquareForDark.png',
				light: './src/assets/LogoSquareForLight.png',
				replacesTitle: true,
			},
			favicon: '/favicon.png',
			social: {
				github: 'https://github.com/hackatorium',
			},
			components: {
				// Override theme selector to hide it
				ThemeSelect: './src/components/Empty.astro',
			  },
			customCss: [
				// Relative path to your custom CSS file
				'./src/styles/custom.css',
			  ],
			sidebar: [
				{
					label: 'CTFs',
					items: [
						{ label: 'TryHackMe CTFs', link: 'ctf/tryhackme/' },
						{
							label: 'Easy',
							collapsed: false,
							items: [
								{ label: 'basicpentestingjt', link: '/ctf/tryhackme/basicpentestingjt/' },
								{ label: 'picklerick', link: '/ctf/tryhackme/picklerick/' },
								{ label: 'rrootme', link: '/ctf/tryhackme/rrootme/' },
								{ label: 'ohsint', link: '/ctf/tryhackme/ohsint/' },
								{ label: 'cowboyhacker', link: '/ctf/tryhackme/cowboyhacker/' },
								{ label: 'crackthehash', link: '/ctf/tryhackme/crackthehash/' },
								{ label: 'inclusion', link: '/ctf/tryhackme/inclusion/' },
								{ label: 'agentsudoctf', link: '/ctf/tryhackme/agentsudoctf/' },
								{ label: 'overpass', link: '/ctf/tryhackme/overpass/' },
								{ label: 'lazyadmin', link: '/ctf/tryhackme/lazyadmin/' },
								{ label: 'ignite', link: '/ctf/tryhackme/ignite/' },
								{ label: 'startup', link: '/ctf/tryhackme/startup/' },
								{ label: 'tomghost', link: '/ctf/tryhackme/tomghost/' },
								{ label: 'chillhack', link: '/ctf/tryhackme/chillhack/' },
								{ label: 'bruteit', link: '/ctf/tryhackme/bruteit/' },
								{ label: 'fowsniff-ctf', link: '/ctf/tryhackme/fowsniff-ctf' }
							]
						},
						{
							label: 'Medium',
							collapsed: false,
							items: [
								{ label: 'mrrobot', link: '/ctf/tryhackme/mrrobot/' },
								{ label: 'dogcat', link: '/ctf/tryhackme/dogcat' }
							]
						},
						{
							label: 'Hard',
							collapsed: false,
							items: [
								{ label: 'dailybugle', link: '/ctf/tryhackme/dailybugle/' },
								{ label: 'internal', link: '/ctf/tryhackme/internal/' }
							]
						}
					]
				},
			],
			head: [
				{
					tag: 'link',
					attrs: {
						rel: 'stylesheet',
						// Choose one of these font combinations:
						//href: 'https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap'
						//href: 'https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Share+Tech+Mono&display=swap'
						// Or:
						href: 'https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@400;700&display=swap'
						// Or:
						// href: 'https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap'
						// Or:
						// href: 'https://fonts.googleapis.com/css2?family=Major+Mono+Display&display=swap'
					}
				},
				// Force dark mode
				{
				  tag: 'script',
				  content: 'document.documentElement.dataset.theme = "dark";'
				}
			  ],
		}),
	],
	markdown: {
		rawContent: true, // Allow raw content to be processed
	},
	// Add this configuration
	assets: {
		fileTypes: ['.log', '.asc', '.py', '.php', '.txt', '.key']
	},
	// This tells Astro where to find static files
	publicDir: 'src/content/docs',
	build: {
		assets: 'assets'
	}
});

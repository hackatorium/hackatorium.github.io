// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
	integrations: [
		starlight({
			title: 'Hackatorium',
			logo: { 
				dark:'./src/assets/LogoSquareForDark.png', 
				light:'./src/assets/LogoSquareForLight.png', 
				replacesTitle: true,
			},
			favicon: '/assets/LogoSquareForDark.png',
			social: {
				github: 'https://github.com/hackatorium',
			},
			customCss: [
				// Path to your custom CSS file
				'/styles/custom.css',
			  ],
			sidebar: [
				// {
				// 	label: 'Guides',
				// 	autogenerate: { directory: 'reference' },
				// },
				// {
				// 	label: 'Reference',
				// 	autogenerate: { directory: 'reference' },
				// },
				// {
				// 	label: 'Tutorials',
				// 	autogenerate: { directory: 'tutorials' },
				// },
				{
					label: 'CTFs',
					items: [
						{ label: 'TryHackMe CTFs', link: 'ctf/tryhackme' },
					]
				},
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

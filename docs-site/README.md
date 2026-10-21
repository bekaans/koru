# docs-site

The Koru documentation site, built with mdBook. Build: `mdbook build docs-site` (mdBook 0.5.4).
Output is under `docs-site/book/` (gitignored). The site is published through GitHub Pages.
Accessibility checklist: images carry `alt` text; the demo GIF's text description is in README.md;
anyone adding a page writes meaningful `alt` for new images and verifies it in the HTML after
`mdbook build` .

# Images Directory

This directory contains images for the actsense documentation.

## Location

Place all documentation images in this directory: `docs/static/images/`

## Usage in Markdown

Reference images in your markdown files using:

```markdown
![Alt text](/images/filename.png)
```

The leading slash (`/`) is important - it references the root of the site.

## File Naming

- Use kebab-case: `graph-visualization.png`
- Be descriptive: `node-details-panel.png`
- Include file extension: `.png`, `.jpg`, `.jpeg`, `.svg`

## Hugo Static Files

Files in the `static/` directory are copied directly to the site root during build. So:
- `docs/static/images/photo.png` → accessible at `/images/photo.png`
- `docs/static/favicon.ico` → accessible at `/favicon.ico`

## Image Guidelines

- **Format**: PNG for screenshots, JPG for photos, SVG for icons
- **Resolution**: Minimum 1920x1080 for full screenshots
- **File Size**: Optimize images to keep page load times fast
- **Alt Text**: Always include descriptive alt text for accessibility

## Current Images

See `../IMAGES_NEEDED.md` for a complete list of required images.



import rss, { pagesGlobToRssItems } from '@astrojs/rss';

export async function GET(context) {
  return rss({
  title: 'K!nd4SUS | Blog',
    description: 'K!nd4SUS Online Blog',
    site: context.site,
    items: await pagesGlobToRssItems(import.meta.glob('./**/*.md')),
    customData: `<language>it</language>`,
  });
}
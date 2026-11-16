import rss, { pagesGlobToRssItems } from '@astrojs/rss';

export async function GET(context) {
  return rss({
    title: 'K!nd4SUS | Blog & Events',
    description: 'K!nd4SUS Online Blog, Writeups & Events',
    site: context.site,
    items: await pagesGlobToRssItems(import.meta.glob('./{blog/posts,events}/*.md')),
    customData: `<language>it</language>`,
  });
}

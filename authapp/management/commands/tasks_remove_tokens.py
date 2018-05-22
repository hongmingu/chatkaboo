from urllib.request import urlopen

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = 'ping sitemaps on google or bing'

    def handle(self, *args, **options):
        urlopen("https://www.bing.com/webmaster/ping.aspx?siteMap=https://www.sajufortune.com/sitemap.xml", timeout=60)
        urlopen("https://www.google.com/webmasters/sitemaps/ping?sitemap=https://www.sajufortune.com/sitemap.xml",
                timeout=60)

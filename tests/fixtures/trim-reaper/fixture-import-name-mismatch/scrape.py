from bs4 import BeautifulSoup

# requirements.txt declares "beautifulsoup4" (the PyPI/installed name),
# but the importable module is "bs4". A source-import search that only
# looks for "beautifulsoup4" would never find this real usage.
def parse(html):
    return BeautifulSoup(html, "html.parser")

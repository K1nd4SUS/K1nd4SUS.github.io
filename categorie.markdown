---
layout: page
title: Categorie
order: 1
permalink: /categorie/
---

{%- assign categories = site.categories | sort -%}
{%- for category in categories -%}

{%- assign categoryName = category[0] -%}
{%- assign categoryNumPosts = category[1] | size -%}
<h2 id="{{categoryName | uri_escape | downcase }}">{{ categoryName }}</h2>

<ul>
    {% assign sorted_posts = category[1] | reversed %}
    {% for post in sorted_posts %}
    <li>
        <a href="{{ post.url }}">{{ post.title }}</a> -
        <time datetime="{{ post.date | date_to_xmlschema }}"
              itemprop="datePublished">{{ post.date | date: "%b %-d, %Y" }}</time>
    </li>
    {% endfor %}
</ul>

{%- endfor -%}
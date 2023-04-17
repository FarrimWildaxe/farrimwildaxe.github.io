---
title: Writeups
date: 2022-04-22T16:46:22+01:00
author: Farrim Wildaxe
order: 4
---
<div id="post-list">
  {% for post in site.categories['Writeup'] %}
    <div class="post-preview">
      <h1><a href="{{ post.url | relative_url }}">{{ post.title }}</a></h1>
      <div class="post-content">
        <p>
          {% include no-linenos.html content=post.content %}
          {{ content | markdownify | strip_html | truncate: 200 | escape }}
        </p>
      </div>
      <div class="post-meta text-muted d-flex">
        <div class="mr-auto">
          <!-- posted date -->
          <i class="far fa-calendar fa-fw"></i>
          {% include datetime.html date=post.date %}
          <!-- categories -->
          {% if post.categories.size > 0 %}
            <i class="far fa-folder-open fa-fw"></i>
            <span>
              {% for category in post.categories %}
              {{ category }}
              {%- unless forloop.last -%},{%- endunless -%}
              {% endfor %}
            </span>
          {% endif %}
        </div> <!-- mr-auto -->
      </div> <!-- .post-meta -->
    </div> <!-- .post-review -->
  {% endfor %}
</div>

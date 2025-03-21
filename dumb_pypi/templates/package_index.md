# {{ package_name }}

Latest version: `{{ requirement }}`

{% if generate_timestamp %}
Generated on {{date}}.
{% endif %}

<!-- This format follows PEP 503 Simple Repository API -->
<ul>
{% for package in packages %}
    <li>
        <a href="{{ package.url }}" data-requires-python="">{{ package.version }}</a>
        ({{ package.info_string }})
    </li>
{% endfor %}
</ul>

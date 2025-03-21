# Simple Package Index

{% if generate_timestamp %}
Generated on {{date}}.
{% endif %}

<!-- This format follows PEP 503 Simple Repository API -->
<ul>
{% for package_name in package_names %}
    <li><a href="{{ package_name }}/">{{ package_name }}</a></li>
{% endfor %}
</ul>

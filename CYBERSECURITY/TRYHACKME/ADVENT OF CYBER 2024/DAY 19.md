![5ed5961c6276df568891c3ea-1732331833645.svg](../../IMAGES/5ed5961c6276df568891c3ea-1732331833645.svg)




Glitch was keen on uncovering Mayor Malware's deeds. Today, he was sure he would find something neat. He knew the Mayor had an office downtown, where he kept his dirty laundry, the big old clown. He approached the site silently, not knowing the door was closed, so untimely. At the front of the door, a smart lock awaited; Glitch smiled cause he knew it could be subverted. But oh, big surprise, the lock was eerie; a game controlled it; Glith almost went teary.

If you are wondering how this came to be, Mayor Malware himself will explain it quickly. "Technology gets broken every day" was his claim, "but nobody knows how to hack a game."

Will Glitch be able to pass through this door, or will he end up with zero as his score?

This is the continuation of [day 18](DAY%2018.md)
## Learning Objectives
---

```ad-summary
- Understand how to interact with an executable'sÂ API.
- Intercept and modify internal APIs using Frida.
- Hack a game with the help of Frida.
```

![Pasted image 20241219114542.png](../../IMAGES/Pasted%20image%2020241219114542.png)

## Game Hacking
---

Even while penetration testing is becoming increasingly popular, game hacking only makes up a small portion of the larger cyber security field. With its 2023 revenue reaching approximately $183.9 billion, the game industry can easily attract attackers. They can do various malicious activities, such as providing illegitimate ways to activate a game, providing bots to automate game actions, or misusing the game logic to simplify it. Therefore, hacking a game can be pretty complex since it requires different skills, including memory management, reverse engineering, and networking knowledge if the game runs online.

## Executables and Libraries
---

TheÂ **executable**Â file of an application is generally understood as a standalone binary file containing the compiled code we want to run. While some applications contain all the code they need to run in their executables,Â many applications usually rely on external code in library files with the "so" extension.

Library files are collections of functions that many applications can reuse. Unlike applications, they can't be directly executed as they serve no purpose by themselves. For a library function to be run, an executable will need to call it. The main idea behind libraries is to pack commonly used functions so developers don't need to reimplement them for every new application they develop.

For example, imagine you are developing a game that requires adding two numbers together. Since mathematical functions are so commonly used, you could implement a library calledÂ `libmaths`Â to handle all your math functions, one of which could be calledÂ `add()`. The function would take two arguments (`x`Â andÂ `y`) and return theÂ `sum`Â of both numbers.

![Pasted image 20241219120527.png](../../IMAGES/Pasted%20image%2020241219120527.png)

Note that the application trusts the library to perform the requested operation correctly. From an attacker's standpoint, if we could somehow intercept the function calls from the executable to the library, we could alter the arguments sent or the return value. This would allow us to force the application to behave in strange ways.Â 

## Hacking with Frida

Frida is a powerful instrumentation tool that allows us to analyze, modify, and interact with running applications. How does it do that? Frida creates a thread in the target process; that thread will execute some bootstrap code that allows the interaction. This interaction, known as the agent, permits the injection of JavaScript code, controlling the application's behavior in real-time. One of the most crucial functionalities of Frida is the Interceptor. This functionality lets us alter internal functions' input or output or observe their behavior. In the example above, Frida would allow us to intercept and change the values ofÂ `x`Â andÂ `y`Â that the library would receive on the fly. It would also allow us to change the returnedÂ `sum`Â value that is sent to the executable:

![Add call function intercepted by Frida](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/5ed5961c6276df568891c3ea-1732337944825.png)  

Let's take a look at a hypothetical example. In this example,Â a number is simply printed on the console.

```shell-session
ubuntu@tryhackme:~$ ./main
Hello, 1!
Hello, 1!
Hello, 1!
Hello, 1!
Hello, 1!
Hello, 1!
Hello, 1!
Hello, 1!
```

What we want to achieve is replacing that value with an arbitrary one, let's say 1337.

Before proceeding, we will runÂ `frida-trace`Â for the first time so that it createsÂ **handlers**Â for each library function used by the game. By editing the handler files, we can tell Frida what to do with the intercepted values of a function call. To have Frida create the handler files, you would run the following command:

`frida-trace ./main -i '*'`

You will now see theÂ `__handlers__`Â directory, containing JavaScript files for each function your application calls from a library. One such function will be calledÂ `say_hello()`Â and have a corresponding handler atÂ `__handlers__/libhello.so/say_hello.js`, allowing us to interact with the target application in real-time.

We don't need to understand what the file does just yet; we will review this later in the task.

Each handler will have two functions known as hooks since they are hooked into the function respectively before and after the function call:

```ad-info
- **onEnter:**Â From this function, we are mainly interested in theÂ `args`Â variable, an array of pointers to the parameters used by our target function - a pointer is just an address to a value.
- **onLeave:**Â here, we are interested in theÂ `retval`Â variable, which will contain a pointer to the variable returned.
```

```javascript
// Frida JavaScript script to intercept `say_hello` 
Interceptor.attach(Module.getExportByName(null, "say_hello"), { 
    onEnter: function (log, args, state) { }, 
    onLeave: function (log, retval, state) { } 
});
```

We have pointers and not just variables because if we change any value, it has to be permanent; otherwise, we will modify a copy of the value, which will not be persistent.

Returning to our objective, we want to set the parameter with 1337. To do so, we must replace the first arguments of the args array:Â `args[0]`Â with a pointer to a variable containing 1337.

Frida has a function calledÂ `ptr()`Â that does exactly what we need: allocate some space for a variable and return its pointer. We also want to log the value of the original argument, and we have to use the functionÂ `toInt32()`, which reads the value of that pointer.

```javascript
// say_hello.js
// Hook the say_hello function from libhello.so

// Attach to the running process of "main"
Interceptor.attach(Module.findExportByName(null, "say_hello"), {
    onEnter: function (args) {
        // Intercept the original argument (args[0] is the first argument)
        var originalArgument = args[0].toInt32();
        console.log("Original argument: " + originalArgument);
        // Replace the original value with 1337
        args[0] = ptr(1337);
        log('say_hello()');
    }
});
```

When we rerun the executable with Frida, we notice that we can intercept the program's logic, setting 1337 as the parameter function. The original value is logged as expected using the following command:


```shell
ubuntu@tryhackme:~$ frida-trace ./main -i 'say*'
Hello, 1337!
Original argument: 1
/* TID 0x5ec9 */
11 ms  say_hello()
Hello, 1337!
Original argument: 1
```


Now that we better understand Frida's capabilities, we can return toÂ `frida-trace`. We have already seen that it generates the JavaScript script to hook a specific function automatically, but how does it know which function needs to be hooked? The parameterÂ `-i`Â tells Frida which library to hook, and it can filter using the wildcard, tracing all the functions in all the libraries loaded.

## TryUnlockMe - The Frostbitten OTP
---

![Glitch hacking the door](https://tryhackme-images.s3.amazonaws.com/user-uploads/63c131e50a24c3005eb34678/room-content/63c131e50a24c3005eb34678-1732645396497.png)  

You can start the game by running the following command on a terminal:

`cdÂ /home/ubuntu/Desktop/TryUnlockMe && ./TryUnlockMe`

![Game Splash screen](https://tryhackme-images.s3.amazonaws.com/user-uploads/63c131e50a24c3005eb34678/room-content/63c131e50a24c3005eb34678-1732294235507.png)

Exploring the game a bit around, you will find a penguin asking for a PIN.

![First level game](https://tryhackme-images.s3.amazonaws.com/user-uploads/63c131e50a24c3005eb34678/room-content/63c131e50a24c3005eb34678-1732292354214.png)  

Terminate the previous game instance and execute the following Frida command to intercept all the functions in theÂ `libaocgame.so`Â library where some of the game logic is present:

`frida-trace ./TryUnlockMe -i 'libaocgame.so!*'`

If you revisit the NPC, you can trigger the OTP function on the console displayed asÂ `set_otpi`

```shell
ubuntu@tryhackme:~/Desktop/TryUnlockMe/$ frida-trace ./TryUnlockMe -i 'libaocgame.so!*'
Instrumenting...                                                        

Started tracing 3 functions. Web UI available at http://localhost:1337/ 
/* TID 0x2240 */
7975 ms  _Z7set_otpi()
```


Notice the outputÂ `_Z7set_otpi`Â indicates that theÂ `set_otp`Â function is called during the NPC interaction; you can try intercepting it!

Open a new terminal, go to theÂ `/home/ubuntu/Desktop/TryUnlockMe/__handlers__/libaocgame.so/`Â folder, and open Visual Studio Code by running:


```shell-session
ubuntu@tryhackme:~$ cd /home/ubuntu/Desktop/TryUnlockMe/__handlers__/libaocgame.so/
ubuntu@tryhackme:~/Desktop/TryUnlockMe/__handlers__/libaocgame.so/$ code .
ubuntu@tryhackme:~/Desktop/TryUnlockMe/__handlers__/libaocgame.so/$
```

![Pasted image 20241219121250.png](../../IMAGES/Pasted%20image%2020241219121250.png)


At this point, you should be able to select theÂ `_Z7set_otpi`Â JavaScript file with the hook defined. The i at the end of theÂ `set_otp`Â function indicates that an integer will be passed as a parameter. It will likely set the OTP by passing it as the first argument. To get the parameter value, you can use theÂ `log`Â function, specifying the first elements of the arrayÂ `args`Â on theÂ `onEnter`Â function:

`log("Parameter:" + args[0].toInt32());`

Your JavaScript file should look like the following:

```javascript
defineHandler({
  onEnter(log, args, state) {
    log('_Z7set_otpi()');
    log("Parameter:" + args[0].toInt32());
  },
  onLeave(log, retval, state) {
  }
});
```

You should be able to log something similar:


```shell-session
ubuntu@tryhackme:~/Desktop/TryUnlockMe/$ frida-trace ./TryUnlockMe -i 'libaocgame.so!*'
Instrumenting...                                                        

Started tracing 3 functions. Web UI available at http://localhost:1337/ 
           /* TID 0x2240 */
 39618 ms  _Z7set_otpi()
 39618 ms  Parameter:611696/code>
```


![Pasted image 20241219122516.png](../../IMAGES/Pasted%20image%2020241219122516.png)


![Pasted image 20241219122540.png](../../IMAGES/Pasted%20image%2020241219122540.png)

Flag 1 is: `THM{one_tough_password}`


## TryUnlockMe - A Wishlist for Billionaires
----
Exploring the new stage, you will find another penguin with a costly item named Right of Pass.

![Game image of the second stage showing the items to buy.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/5ed5961c6276df568891c3ea-1732808985706.png)  

The game lets you earn coins by using the old PC on the field, but getting 1.000.000 coins that way sounds tedious. You can again use Frida to intercept the function in charge of purchasing the item. This time is a bit more tricky than the previous one because the functionÂ `buy_item`Â displayed as:Â `_Z17validate_purchaseiii`Â has three i letters after its name to indicate that it has three integer parameters.  

You can log those values using the log function for each parameter trying to buy something:

`log("Parameter1:" + args[0].toInt32())`  
`log("Parameter2:" + args[1].toInt32())`  
`log("Parameter3:" + args[2].toInt32())`


Your JavaScriptÂ `buy_item`Â file should look like the following:  

```javascript
defineHandler({
  onEnter(log, args, state) {
    log('_Z17validate_purchaseiii()');
    log('PARAMETER 1: '+ args[0]);
    log('PARAMETER 2: '+ args[1]);
    log('PARAMETER 3: '+ args[2]);

  },

  onLeave(log, retval, state) {
      
  }
});
```

You should be able to log something similar:


```shell-session
07685 ms  _Z17validate_purchaseiii()
365810 ms  PARAMETER 1: 0x1
365810 ms  PARAMETER 2: 0x5
365810 ms  PARAMETER 3: 0x1
```

By simple inspection, we can determine that the first parameter is the Item ID, the second is the price, and the third is the player's coins. If you manipulate the price and set it as zero, you can buy any item that you want:

`args[1] = ptr(0)`

Your JavaScript buy_item file should look like the following:

```javascript
defineHandler({
  onEnter(log, args, state) {
    log('_Z17validate_purchaseiii()');
    args[1] = ptr(0)

  },

  onLeave(log, retval, state) {
      
  }
});
```


![Pasted image 20241219123032.png](../../IMAGES/Pasted%20image%2020241219123032.png)

Flag 2 is: `THM{credit_card_undeclined}`

You can buy any item now!

## TryUnlockMe - Naughty Fingers, Nice Hack
---

![Game third level](https://tryhackme-images.s3.amazonaws.com/user-uploads/63c131e50a24c3005eb34678/room-content/63c131e50a24c3005eb34678-1732659104183.png)  

This last stage is a bit more tricky because the output displayed by Frida isÂ `_Z16check_biometricsPKc()`, so it does not handle integers anymore but strings making a bit more complex to debug.

By selecting the JavaScript file namedÂ `_Z16check_biometricsPKc`, you can add the following code to theÂ `onEnter()`Â function as you did previously to debug the content of the parameter:

```javascript
defineHandler({
  onEnter(log, args, state) {
    log('_Z16check_biometricsPKc()');
    log("PARAMETER:" + Memory.readCString(args[0]))
  },

  onLeave(log, retval, state) {
  }
});
```

You should be able to log something similar:


```shell-session
1279884 ms  _Z16check_biometricsPKc()
1279884 ms  PARAMETER:1trYRV2vJImp9QiGEreHNmJ8LUNMyfF0W4YxXYsqrcdy1JEDArUYbmguE1GDgUDA
```

This output does not seem very helpful; you may have to consider another way. You can log the return value of the function by adding the following log instruction in theÂ `onLeave`Â function:

```javascript
onLeave(log, retval, state) {
    log("The return value is: " + retval);
  }
});
```

You should be able to log something similar:


```shell-session
69399931 ms  The return value is: 0x0
```

So, the value returned is 0, which may indicate that it is a boolean flag set to False. Which value will set it to True? Can you trick the game into thinking the biometrics check worked?

The following instruction will set it the return value to True:  
`retval.replace(ptr(1))`

So, code would be the following: 

```js
defineHandler({
  onEnter(log, args, state) {
    log('_Z16check_biometricsPKc()');
    log('PARAMETER:' + Memory.readCString(args[0]))
  },

  onLeave(log, retval, state) {
    retval.replace(ptr(1));
    log("The return value is: " + retval);
  }
});
```


![Pasted image 20241219123643.png](../../IMAGES/Pasted%20image%2020241219123643.png)

So, final flag would be: `THM{dont_smash_your_keyboard}`


## Questions
---

![Pasted image 20241219123757.png](../../IMAGES/Pasted%20image%2020241219123757.png)


Just like that, day 19 is done!


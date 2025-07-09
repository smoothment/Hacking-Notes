---
sticker: lucide//curly-braces
---

---

In addition to web servers that can host web applications in various languages, there are many common web development frameworks that help in developing core web application files and functionality. With the increased complexity of web applications, it may be challenging to create a modern and sophisticated web application from scratch. Hence, most of the popular web applications are developed using web frameworks.

As most web applications share common functionality -such as user registration-, web development frameworks make it easy to quickly implement this functionality and link them to the front end components, making a fully functional web application. Some of the most common web development frameworks include:

- [Laravel](https://laravel.com/)Â (`PHP`): usually used by startups and smaller companies, as it is powerful yet easy to develop for.
- [Express](https://expressjs.com/)Â (`Node.JS`): used byÂ `PayPal`,Â `Yahoo`,Â `Uber`,Â `IBM`, andÂ `MySpace`.
- [Django](https://www.djangoproject.com/)Â (`Python`): used byÂ `Google`,Â `YouTube`,Â `Instagram`,Â `Mozilla`, andÂ `Pinterest`.
- [Rails](https://rubyonrails.org/)Â (`Ruby`): used byÂ `GitHub`,Â `Hulu`,Â `Twitch`,Â `Airbnb`, and evenÂ `Twitter`Â in the past.

It must be noted that popular websites usually utilize a variety of frameworks and web servers, rather than just one.

---

## APIs

An important aspect of back end web application development is the use of WebÂ [APIs](https://en.wikipedia.org/wiki/API)Â and HTTP Request parameters to connect the front end and the back end to be able to send data back and forth between front end and back end components and carry out various functions within the web application.

For the front end component to interact with the back end and ask for certain tasks to be carried out, they utilize APIs to ask the back end component for a specific task with specific input. The back end components process these requests, perform the necessary functions, and return a certain response to the front end components, which finally renderers the end user's output on the client-side.

---

#### Query Parameters

The default method of sending specific arguments to a web page is throughÂ `GET`Â andÂ `POST`Â request parameters. This allows the front end components to specify values for certain parameters used within the page for the back end components to process them and respond accordingly.

For example, aÂ `/search.php`Â page would take anÂ `item`Â parameter, which may be used to specify the search item. Passing a parameter through aÂ `GET`Â request is done through the URL '`/search.php?item=apples`', whileÂ `POST`Â parameters are passed throughÂ `POST`Â data at the bottom of theÂ `POST`Â `HTTP`Â request:

Code:Â http

```http
POST /search.php HTTP/1.1
...SNIP...

item=apples
```

Query parameters allow a single page to receive various types of input, each of which can be processed differently. For certain other scenarios, Web APIs may be much quicker and more efficient to use. TheÂ [Web Requests module](https://academy.hackthebox.com/course/preview/web-requests)Â takes a deeper dive intoÂ `HTTP`Â requests.

---

## Web APIs

An API ([Application Programming Interface](https://en.wikipedia.org/wiki/API)) is an interface within an application that specifies how the application can interact with other applications. For Web Applications, it is what allows remote access to functionality on back end components. APIs are not exclusive to web applications and are used for software applications in general. Web APIs are usually accessed over theÂ `HTTP`Â protocol and are usually handled and translated through web servers.

![API examples](https://academy.hackthebox.com/storage/modules/75/api_examples.jpg)

A weather web application, for example, may have a certain API to retrieve the current weather for a certain city. We can request the API URL and pass the city name or city id, and it would return the current weather in aÂ `JSON`Â object. Another example is Twitter's API, which allows us to retrieve the latest Tweets from a certain account inÂ `XML`Â orÂ `JSON`Â formats, and even allows us to send a Tweet 'if authenticated', and so on.

To enable the use of APIs within a web application, the developers have to develop this functionality on the back end of the web application by using the API standards likeÂ `SOAP`Â orÂ `REST`.

---

## SOAP

TheÂ `SOAP`Â ([Simple Objects Access](https://en.wikipedia.org/wiki/SOAP)) standard shares data throughÂ `XML`, where the request is made inÂ `XML`Â through an HTTP request, and the response is also returned inÂ `XML`. Front end components are designed to parse thisÂ `XML`Â output properly. The following is an exampleÂ `SOAP`Â message:

Code:Â xml

```xml
<?xml version="1.0"?>

<soap:Envelope
xmlns:soap="http://www.example.com/soap/soap/"
soap:encodingStyle="http://www.w3.org/soap/soap-encoding">

<soap:Header>
</soap:Header>

<soap:Body>
  <soap:Fault>
  </soap:Fault>
</soap:Body>

</soap:Envelope>
```

`SOAP`Â is very useful for transferring structured data (i.e., an entire class object), or even binary data, and is often used with serialized objects, all of which enables sharing complex data between front end and back end components and parsing it properly. It is also very useful for sharingÂ _stateful_Â objects -i.e., sharing/changing the current state of a web page-, which is becoming more common with modern web applications and mobile applications.

However,Â `SOAP`Â may be difficult to use for beginners or require long and complicated requests even for smaller queries, like basicÂ `search`Â orÂ `filter`Â queries. This is where theÂ `REST`Â API standard is more useful.

---

## REST

TheÂ `REST`Â ([Representational State Transfer](https://en.wikipedia.org/wiki/Representational_state_transfer)) standard shares data through the URL path 'i.e.Â `search/users/1`', and usually returns the output inÂ `JSON`Â format 'i.e. useridÂ `1`'.

Unlike Query Parameters,Â `REST`Â APIs usually focus on pages that expect one type of input passed directly through the URL path, without specifying its name or type. This is usually useful for queries likeÂ `search`,Â `sort`, orÂ `filter`. This is whyÂ `REST`Â APIs usually break web application functionality into smaller APIs and utilize these smaller API requests to allow the web application to perform more advanced actions, making the web application more modular and scalable.

Responses toÂ `REST`Â API requests are usually made inÂ `JSON`Â format, and the front end components are then developed to handle this response and render it properly. Other output formats forÂ `REST`Â includeÂ `XML`,Â `x-www-form-urlencoded`, or even raw data. As seen previously in theÂ `database`Â section, the following is an example of aÂ `JSON`Â response to theÂ `GET /category/posts/`Â API request:

Code:Â json

```json
{
  "100001": {
    "date": "01-01-2021",
    "content": "Welcome to this web application."
  },
  "100002": {
    "date": "02-01-2021",
    "content": "This is the first post on this web app."
  },
  "100003": {
    "date": "02-01-2021",
    "content": "Reminder: Tomorrow is the ..."
  }
}
```

`REST`Â uses various HTTP methods to perform different actions on the web application:

- `GET`Â request to retrieve data
- `POST`Â request to create data (non-idempotent)
- `PUT`Â request to create or replace existing data (idempotent)
- `DELETE`Â request to remove data


# Question
---




![Pasted image 20250122185309.png](../../../../IMAGES/Pasted%20image%2020250122185309.png)

We can use curl for this: `curl 'http://94.237.62.3:33241/index.php?id=1'`

And we'll get: `superadmin`


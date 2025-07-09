<div style="text-align: center;">
	TCP CLIENT AND SERVER
</div>


Para iniciar con esta secciÃ³n de Python para pentesters, hablaremos un poco de como realizar un cliente y un servidor en TCP usando Python y mas especificamente su modulo socket.

Primero, hay que entender que el modulo socket es usado en python para el manejo de redes, este modulo contiene todas las piezas necesarias para escribir de manera rapida y efetiva el protocolo TCP y UDP, en repetidas ocasiones, al realizar un pentest, tenemos que tener un cliente TCP para testear servicios, enviar datos "basura" o realizar multiples tareas, si estamos trabajando en los confines de una empresa, no tendremos el lujo de usar herramientas de redes o compiladores, en casos mas extremos, no tendremos ni siquiera la habilidad para copiar y pegar o conectarnos al internet, es entonces cuando crear un cliente de TCP es bastante util, este es el ejemplo de un cliente TCP sencillo:


<div style="text-align: center;"> TCP CLIENT
</div>

```run-python
import socket # Empezaremos importando el modulo, este viene instalado por                    defecto en python.

TARGET_HOST = '0.0.0.0' # Especificaremos el HOST de nuestro target.
TARGET_PORT = 80 # Especificamos el PUERTO del target

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # creamos un objeto de la clase socket, siempre se crea de esta forma si nos referimos al protocolo TCP

client.connect((TARGET_HOST, TARGET_PORT)) # Nos conectamos al target usando su host y su puerto

client.send(b"ABCDEF") # Enviamos algunos datos

response = client.recv(4096) # Para recibir datos

print(response.decode()) # Decodificamos la respuesta para que peuda ser leida en un lenguaje humano

client.close() # Cerramos la conexiÃ³n.
```


A simple vista, parece un codigo algo complicado y no hay muchas bases que nos digan que significa cada cosa, por lo que, desglosaremos este codigo paso a paso: 

1. Se crea un objeto de la clase socket con el parametro `AF_INET` el cual se encarga de especificar que usaremos una direcciÃ³n estandar IPV4 o un hostname, el parametro `SOCK_STREAM` se encarga de indicar que estamos usando un cliente TCP.
2. Nos conectamos al cliente.
3. Enviamos algunos datos en forma de bytes.
4. Recibimos algunos datos de respuesta y la imprimimos conviertendolo de bytes a un sistema legible para personas.

Esta es la forma mas sencilla de un cliente TCP, pero es el que se codea mas frecuentemente.


Procederemos ahora a codear un servidor TCP que nos puede ser de utilidad al momento de escribir command shells, crear proxies y demÃ¡s, creemos un servidor TCP multihilo:

```run-python
import socket
import threading

IP = '0.0.0.0'
PORT = 9998


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # 1
    server.bind((IP, PORT)) # 2
    server.listen(5)
    print(f'[*] Listening on {IP}:{PORT}')

    while True:
        client, address = server.accept() # 3
        print(f'[*] Accepted connection from {address[0]}:{address[1]}')
	    client_handler = threading.Thread(target=handle_client,                                                      args=(client,))
        client_handler.start() # 4

def handle_client(client_socket): # 5
    with client_socket as sock:
        request = sock.recv(1024)
        print(f'[*] Received: {request.decode("utf-8")}')
        sock.send(b'ACK')

if __name__ == '__main__':
    main()
```


EXPLICACION:

1. Pasamos la IP y el Puerto en el que queremos escuchar.
2. Le decimos al server que inicie la escucha con un retraso maximo de conexiones de 5.
3. Entramos en el ciclo principal, en el que se encarga de esperar una conexion.
4. Cuando un cliente se conecta, recibimos el socket del cliente en la variable `client` y los detalles de la conexion remota en la variable `address`.
5. Creamos un hilo que apunta a nuestra funcion `handle_client` y le pasamos el socket del cliente como parametro, despues, inicializamos el hilo para que se encargue de manejar la conexion del cliente.
6. En un punto, el ciclo principal, es capaz de manejar otra conexion entrante.
7. La funcion `handle_client` realiza el `recv()` y envia un mensaje simple de vuelta al cliente.

Si usamos el cliente TCP de la secciÃ³n anterior, podemos enviar algunos paquetes al servidor, al probarlo, obtenemos un output de este modo:

```
[*] Listening on 0.0.0.0:9998
[*] Accepted connection from: 127.0.0.1:62512
[*] Received: ABCDEF
```

Y eso es todo, si bien es simple, es muy util.

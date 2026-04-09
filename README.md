  1 [![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/mz56G3Dy)
# Lab 5
Eric Hoang

CSCI 3762-001

## Description

In this lab, I created a client (client.c) that accepts a file directory (FILES) chunks each file into 512KB chunks, then hashes each chunk using SHA256. Each chunk file is named by its SHA256 hash and added to a directory (CHUNKS) inside of FILES. This file information is then sent to the server.

Ther server receives the JSON data, parses it with cJSON, and then stores the file information in a linked list. Duplicate entries with the same IP address and port number combincation are not entered. The stored file infomration is then printed.


### Executing program

* How to run the program (client side)
```
./client 224.0.0.1 1818 FILES
```

(server side)
```
./server 224.0.0.1 1818 
```


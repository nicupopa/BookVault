# README

## Project Overview

This project is a C-based web client that interacts with a REST API using HTTP requests. It includes functionalities for sending GET, POST, and DELETE requests and can handle server responses, including JSON parsing, cookies, and authorization tokens.

### Key Features
- **Sending HTTP Requests**: The project supports sending GET, POST, and DELETE requests to a server, with or without cookies and authorization headers.
- **Handling Responses**: The program can extract JSON responses, handle cookies, and manage server connections.
- **Library Access**: The client interacts with an API to perform actions such as logging in, entering a library, and performing CRUD operations on books.
- **JSON Parsing**: The project uses the Parson library for JSON operations.

### How to Build and Run

#### Compilation
1. To compile the project, run the following command:
   ```bash
   make
#### Execution
2. After compiling, you can run the client:

    ```bash
    ./client
### Available Commands
- **register**: Register a new user by providing username and password.
- **login**: Log in with the registered credentials.
- **enter_library**: Gain access to the library after logging in.
- **get_books**: Retrieve the list of books from the library.
- **add_book**: Add a new book to the library by providing its details.
- **delete_book**: Delete a book from the library by specifying its ID.
- **logout**: Log out and terminate the current session.

## Request and Response Handling
- **GET Requests**: The client supports sending GET requests to retrieve resources.
- **POST Requests**: The client can send POST requests with JSON bodies to create new resources.
- **DELETE Requests**: Delete requests are used to remove resources from the server.

Cookies and authorization tokens are automatically handled by the client and included in subsequent requests once retrieved from the server.

## JSON Parsing
The project uses the Parson library for handling JSON. JSON objects are constructed and parsed to handle communication with the server.

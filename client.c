#include <stdio.h>      /* printf, sprintf */
#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include "helpers.h"
#include "requests.h"
#include "parson.h"
#include <ctype.h>

#define COOKIE_NR 10
#define IP "34.246.184.49"
#define PORT 8080

char *credentials() {
    char input[BUFLEN];

    // print at stdout and read credentials
    printf("username=");
    fgets(input, BUFLEN, stdin);
    input[strcspn(input, "\n")] = 0;

    char *username = strdup(input);

    printf("password=");
    fgets(input, BUFLEN, stdin);
    input[strcspn(input, "\n")] = 0;

    char *password = strdup(input);

    if (strchr(password, ' ') || strchr(username, ' ')) {
        printf("ERROR - Credentials can't contain spaces\n");
        free(username);
        free(password);
        return NULL;
    }

    // create json object
    JSON_Value *credentials_val = json_value_init_object();
    JSON_Object *credentials_obj = json_value_get_object(credentials_val);
    json_object_set_string(credentials_obj, "username", username);
    json_object_set_string(credentials_obj, "password", password);
    char *json_str = json_serialize_to_string_pretty(credentials_val);
    
    if (json_str == NULL) {
        return NULL;
    }

    free(username);
    free(password);
    json_value_free(credentials_val);

    return json_str;
}

char* retrieve_cookie(char* response) {
    char* header_line;
    char *cookie = NULL;

    while ((header_line = strtok(NULL, "\r\n"))) {
        if (strstr(header_line, "Set-Cookie:") == header_line) {
            cookie = strdup(header_line + strlen("Set-Cookie: "));
            break;
        }
    }

    return cookie;
}

char* retrieve_token(char* json_response) {
    // parse json
    JSON_Value *root_value;
    JSON_Object *root_object;
    char* token;

    char* extracted_rsp = basic_extract_json_response(json_response);
    root_value = json_parse_string(extracted_rsp);
    if (root_value == NULL) {
        printf("ERROR - Parsing JSON\n");
        return NULL;
    }

    root_object = json_value_get_object(root_value);
    if (root_object == NULL) {
        json_value_free(root_value);
        printf("ERROR - Getting JSON object\n");
        return NULL;
    }

    // retrieve token from json
    const char* token_str = json_object_get_string(root_object, "token");
    if (token_str == NULL) {
        json_value_free(root_value);
        printf("ERROR - Token not found\n");
        return NULL;
    }

    token = strdup(token_str);
    if (token == NULL) {
        printf("ERROR - Memory allocation failed\n");
        return NULL;
    }

    json_value_free(root_value);
    
    return token;
}

char* get_id_url() {
    char input[BUFLEN];

    printf("id=");
    fgets(input, BUFLEN, stdin);
    input[strcspn(input, "\n")] = 0;

    if (input[0] == '\0') {
        printf("ERROR - Please enter an ID\n");
        return NULL;
    }

    // check if id consists of numbers
    for (int i = 0; input[i] != '\0'; i++) {
        if (!isdigit(input[i])) {
            printf("ERROR - ID should consist of numbers\n");
            return NULL;
        }
    }

    char* base_url = "/api/v1/tema/library/books/";
    char *url = calloc(strlen(base_url) + strlen(input) + 1, sizeof(char));
    if (url == NULL) {
        printf("ERROR - URL allocation failed\n");
        return NULL;
    }

    // make final url
    strcpy(url, base_url);
    strcat(url, input);

    return url;
}

char* add_book_prompt() {
    char title[BUFLEN];
    char author[BUFLEN];
    char genre[BUFLEN];
    char publisher[BUFLEN];
    char page_count[BUFLEN];
    long pages;

    // input book data
    printf("title=");
    fgets(title, BUFLEN, stdin);
    title[strcspn(title, "\n")] = 0;

    printf("author=");
    fgets(author, BUFLEN, stdin);
    author[strcspn(author, "\n")] = 0;

    printf("genre=");
    fgets(genre, BUFLEN, stdin);
    genre[strcspn(genre, "\n")] = 0;

    printf("publisher=");
    fgets(publisher, BUFLEN, stdin);
    publisher[strcspn(publisher, "\n")] = 0;

    printf("page_count=");
    fgets(page_count, BUFLEN, stdin);
    page_count[strcspn(page_count, "\n")] = 0;

    if (title[0] == '\0' || author[0] == '\0' || genre[0] == '\0' || publisher[0] == '\0' || page_count[0] == '\0') {
        printf("ERROR - You shouldn't leave any blank fields\n");
        return NULL;
    }

    // verify if page count is a number
    for (int i = 0; i < strlen(page_count); i++) {
        if (!isdigit(page_count[i])) {
            printf("ERROR - Page count should consist of numbers\n");
            return NULL;
        }
    }
    
    pages = atof(page_count);

    // create json object
    JSON_Value *root = json_value_init_object();
    JSON_Object *root_obj = json_value_get_object(root);

    json_object_set_string(root_obj, "title", title);
    json_object_set_string(root_obj, "author", author);
    json_object_set_string(root_obj, "genre", genre);
    json_object_set_number(root_obj, "page_count", pages);
    json_object_set_string(root_obj, "publisher", publisher);

    char *json_str = json_serialize_to_string_pretty(root);
    
    if (json_str == NULL) {
        return NULL;
    }

    json_value_free(root);

    return json_str;
}


int main(int argc, char *argv[])
{
    // initial definitions
    // input buffer and cookies allocation
    char input[BUFLEN];
    memset(input, 0, BUFLEN);
    int login = 0;


    int cookie_max = COOKIE_NR;
    int cookie_counter = 0;
    char* auth = NULL;

    char** cookies = (char **) calloc(COOKIE_NR, sizeof(char *));
    if (cookies == NULL) {
        error("ERROR - Cookies Allocation");
    }

    // reading from stdin
    while (1) {
        fgets(input, BUFLEN, stdin);

        if (strcmp(input, "register\n") == 0) {
            // retrieve credentials
            char* string_body_data = credentials();
            if (string_body_data == NULL) {
                continue;
            }

            // make json message as array of strings for compute_post_request
            char **json_array = malloc(sizeof(char *));
            json_array[0] = string_body_data;

            char* msg = compute_post_request(IP, "/api/v1/tema/auth/register",
                "application/json", json_array, 1, NULL, 0);
            
            // connect to server and send msg
            int sockfd = open_connection(IP, PORT, AF_INET, SOCK_STREAM, 0);
            send_to_server(sockfd, msg);
            char* response = receive_from_server(sockfd);
            close_connection(sockfd);
            
            // process http resonse
            int status_code;
            char status_message[256];
            char *status_line = strtok(response, "\r\n");

            if (status_line) {
                sscanf(status_line, "HTTP/%*d.%*d %d %[^\r\n]",
                    &status_code, status_message);

                if (status_code == 200 || status_code == 201) {
                    printf("%d - %s - SUCCESS\n", status_code, status_message);
                } else {
                    // for security reasons, can't say that user is registered
                    printf("%d - %s - ERR0R\n", status_code, status_message);
                }
            } else {
                printf("Unexpected ERROR\n");
            }
            
            free(json_array);
            free(response);

        } else if (strcmp(input, "login\n") == 0) {
            // ask for credentials
            char* login_credentials;

            if (login == 0) {
                login_credentials = credentials();
                if (login_credentials == NULL) {
                    continue;
                }
                login = 1;
            } else {
                printf("ERROR - You are already logged in\n");
                continue;
            }

            char* cookie = NULL;
            
            // make json message as array of strings for compute_post_request
            char **json_array = malloc(sizeof(char *));
            json_array[0] = login_credentials;

            char* msg = compute_post_request(IP, "/api/v1/tema/auth/login",
                "application/json", json_array, 1, NULL, 0);
            
            int sockfd = open_connection(IP, PORT, AF_INET, SOCK_STREAM, 0);
            send_to_server(sockfd, msg);
            char* response = receive_from_server(sockfd);
            close_connection(sockfd);
            // safety measure for strtok
            char* response_copy = strdup(response);

            // process http resonse
            int status_code;
            char status_message[256];
            char *status_line = strtok(response_copy, "\r\n");

            if (status_line) {
                sscanf(status_line, "HTTP/%*d.%*d %d %[^\r\n]",
                    &status_code, status_message);

                if (status_code == 200 || status_code == 201) {
                    printf("%d - %s - SUCCESS\n", status_code, status_message);

                    // retrieve cookies
                    cookie = retrieve_cookie(response);
                } else {
                    printf("%d - %s - ERR0R\n", status_code, status_message);
                }
            } else {
                printf("Unexpected ERROR\n");
            }

            if (cookie == NULL)
                continue;

            // reallocate memory if necessary
            if (cookie_counter == cookie_max) {
                cookie_max *= 2;
                cookies = realloc(cookies, cookie_max * sizeof(char *));
                if (cookies == NULL) {
                    error("ERROR - Cookies realloc failed");
                }
            }

            // add cookie to cookie list
            cookies[cookie_counter++] = cookie;

            free(json_array);
            free(response);
            free(response_copy);
        } else if (strcmp(input, "enter_library\n") == 0) {
            if (auth != NULL) {
                printf("ERROR - You already have library access\n");
                continue;
            }

            char* cookie = NULL;

            if (cookie_counter > 0) {
                // Compute get request
                char* msg = compute_get_request(IP, "/api/v1/tema/library/access", NULL, cookies, cookie_counter);

                int sockfd = open_connection(IP, PORT, AF_INET, SOCK_STREAM, 0);
                send_to_server(sockfd, msg);
                char* response = receive_from_server(sockfd);
                close_connection(sockfd);

                if (response == NULL) {
                    printf("ERROR - No response from server\n");
                    continue;
                }

                char* response_copy = strdup(response);
                if (response_copy == NULL) {
                    printf("ERROR - strdup failed\n");
                    free(response);
                    continue;
                }

                // process HTTP response
                int status_code;
                char status_message[256];
                char *status_line = strtok(response_copy, "\r\n");

                if (status_line) {
                    sscanf(status_line, "HTTP/%*d.%*d %d %[^\r\n]", &status_code, status_message);
                        if (status_code == 200 || status_code == 201) {
                            // retrieve token
                            auth = retrieve_token(response);
                            cookie = retrieve_cookie(response);
                            printf("%d - %s - SUCCESS\n", status_code, status_message);
                        } else {
                            printf("%d - %s - ERROR\n", status_code, status_message);
                        }
                } else {
                    printf("Unexpected ERROR\n");
                }

                if (cookie == NULL) {
                    free(response);
                    free(response_copy);
                    continue;
                }

                // Reallocate memory if necessary
                if (cookie_counter == cookie_max) {
                    cookie_max *= 2;
                    cookies = realloc(cookies, cookie_max * sizeof(char *));
                    if (cookies == NULL) {
                        error("ERROR - Cookies realloc failed");
                    }
                }

                // Add cookie to cookie list
                cookies[cookie_counter++] = cookie;

                free(response);
                free(response_copy);
            } else {
                printf("ERROR - You should log in first\n");
            }
        } else if (strcmp(input, "get_books\n") == 0) {
            if (auth == NULL) {
                printf("ERROR - You don't have access to the library\n");
                continue;
            }

            char* msg = compute_get_request_auth(IP, "/api/v1/tema/library/books",
                NULL, cookies, cookie_counter, auth);

            int sockfd = open_connection(IP, PORT, AF_INET, SOCK_STREAM, 0);
            send_to_server(sockfd, msg);
            char* response = receive_from_server(sockfd);
            close_connection(sockfd);
            // safety measure for strtok
            char* response_copy = strdup(response);

            // process http resonse
            int status_code;
            char status_message[256];
            char *status_line = strtok(response_copy, "\r\n");

            if (status_line) {
                    sscanf(status_line, "HTTP/%*d.%*d %d %[^\r\n]", &status_code, status_message);
                        if (status_code == 200 || status_code == 201) {
                            // retrieve token
                            printf("%d - %s - SUCCESS\n", status_code, status_message);
                            char* json_response = strstr(response, "[");
                            
                            if (json_response == NULL) {
                                printf("You don't have any books yet\n");
                            } else {
                                printf("%s\n", json_response);
                            }
                        } else {
                            printf("%d - %s - ERROR\n", status_code, status_message);
                        }
                } else {
                    printf("Unexpected ERROR\n");
                }

                free(response_copy);
                free(response);
        } else if (strcmp(input, "add_book\n") == 0) {
            if (auth == NULL) {
                printf("ERROR - You don't have access to the library\n");
                continue;
            }

            char* book_data = add_book_prompt();
            if (book_data == NULL) {
                continue;
            }

            // make json message as array of strings for compute_post_request
            char **json_array = malloc(sizeof(char *));
            json_array[0] = book_data;

            char* msg = compute_post_request_auth(IP, "/api/v1/tema/library/books",
                "application/json", json_array, 1, cookies, cookie_counter, auth);

            int sockfd = open_connection(IP, PORT, AF_INET, SOCK_STREAM, 0);
            send_to_server(sockfd, msg);
            char* response = receive_from_server(sockfd);
            close_connection(sockfd);

            if (response == NULL) {
                printf("ERROR - No response from server\n");
                continue;
            }
                // printf("%s\n", response);
            char* response_copy = strdup(response);
            if (response_copy == NULL) {
                printf("ERROR - strdup failed\n");
                free(response);
                continue;
            }

            // process HTTP response
            int status_code;
            char status_message[256];
            char *status_line = strtok(response_copy, "\r\n");
            
            if (status_line) {
                sscanf(status_line, "HTTP/%*d.%*d %d %[^\r\n]", &status_code, status_message);
                    if (status_code == 200 || status_code == 201) {
                        printf("%d - %s - SUCCESS\n", status_code, status_message);
                    } else {
                        printf("%d - %s - ERROR\n", status_code, status_message);
                    }
            } else {
                printf("Unexpected ERROR\n");
            }

            free(response_copy);
            free(response);
            free(json_array);
        } else if (strcmp(input, "get_book\n") == 0) {
            if (auth == NULL) {
                printf("ERROR - You don't have access to the library\n");
                continue;
            }

            char* payload = get_id_url();
            if (payload == NULL) {
                continue;
            }

            char* msg = compute_get_request_auth(IP, payload,
                NULL, cookies, cookie_counter, auth);

            int sockfd = open_connection(IP, PORT, AF_INET, SOCK_STREAM, 0);
            send_to_server(sockfd, msg);
            char* response = receive_from_server(sockfd);
            close_connection(sockfd);

            if (response == NULL) {
                printf("ERROR - No response from server\n");
                continue;
            }

            char* response_copy = strdup(response);
            if (response_copy == NULL) {
                printf("ERROR - strdup failed\n");
                free(response);
                continue;
            }

            // process HTTP response
            int status_code;
            char status_message[256];
            char *status_line = strtok(response_copy, "\r\n");
            
            if (status_line) {
                sscanf(status_line, "HTTP/%*d.%*d %d %[^\r\n]", &status_code, status_message);
                    if (status_code == 200 || status_code == 201) {
                        printf("%d - %s - SUCCESS\n", status_code, status_message);
                        char* json_response = strstr(response, "{");
                        printf("%s\n", json_response);
                    } else {
                        printf("%d - %s - ERROR\n", status_code, status_message);
                    }
            } else {
                printf("Unexpected ERROR\n");
            }
            free(response_copy);
            free(response);
            free(payload);

        } else if (strcmp(input, "delete_book\n") == 0) {
            if (auth == NULL) {
                printf("ERROR - You don't have access to the library\n");
                continue;
            }

            char* payload = get_id_url();
            if (payload == NULL) {
                continue;
            }

            char* msg = compute_delete_request(IP, payload,
                NULL, cookies, cookie_counter, auth);

            int sockfd = open_connection(IP, PORT, AF_INET, SOCK_STREAM, 0);
            send_to_server(sockfd, msg);
            char* response = receive_from_server(sockfd);
            close_connection(sockfd);

            if (response == NULL) {
                printf("ERROR - No response from server\n");
                continue;
            }

            char* response_copy = strdup(response);
            if (response_copy == NULL) {
                printf("ERROR - strdup failed\n");
                free(response);
                continue;
            }

            // process HTTP response
            int status_code;
            char status_message[256];
            char *status_line = strtok(response_copy, "\r\n");
            
            if (status_line) {
                sscanf(status_line, "HTTP/%*d.%*d %d %[^\r\n]", &status_code, status_message);
                    if (status_code == 200 || status_code == 201) {
                        printf("%d - %s - SUCCESS\n", status_code, status_message);
                    } else {
                        printf("%d - %s - ERROR\n", status_code, status_message);
                    }
            } else {
                printf("Unexpected ERROR\n");
            }

            free(response_copy);
            free(response);
            free(payload);

        } else if (strcmp(input, "logout\n") == 0) {
            if (cookie_counter == 0) {
                printf("ERROR - You are not logged in\n");
                continue;
            }

            char* msg = compute_get_request(IP, "/api/v1/tema/auth/logout",
                NULL, cookies, cookie_counter);

            int sockfd = open_connection(IP, PORT, AF_INET, SOCK_STREAM, 0);
            send_to_server(sockfd, msg);
            char* response = receive_from_server(sockfd);
            close_connection(sockfd);

            if (response == NULL) {
                printf("ERROR - No response from server\n");
                continue;
            }

            char* response_copy = strdup(response);
            if (response_copy == NULL) {
                printf("ERROR - strdup failed\n");
                free(response);
                continue;
            }

            // process HTTP response
            int status_code;
            char status_message[256];
            char *status_line = strtok(response_copy, "\r\n");
            
            if (status_line) {
                sscanf(status_line, "HTTP/%*d.%*d %d %[^\r\n]", &status_code, status_message);
                    if (status_code == 200 || status_code == 201) {
                        printf("%d - %s - SUCCESS\n", status_code, status_message);
                        login = 0;
                    } else {
                        printf("%d - %s - ERROR\n", status_code, status_message);
                    }
            } else {
                printf("Unexpected ERROR\n");
            }

            if (auth != NULL) {
                free(auth);
                auth = NULL;
            }

            for (int i = 0; i < cookie_counter; i++) {
                free(cookies[i]);
                cookies[i] = NULL;
            }

            cookie_counter = 0;
            free(response_copy);
            free(response);

        } else if (strcmp(input, "exit\n") == 0) {
            printf("SUCCESS - Goodbye\n");
            break;
        } else {
            printf("ERROR - Invalid input\n");
        }
    }

    // i want to break free from your lies
    for (int i = 0; i < cookie_counter; i++) {
        free(cookies[i]);
    }
    free(cookies);


    return 0;
}


# REST API – Flask Implementation (`distributed_environment_api.py`)

> Unit 7 Activity – Application Programming Interface (API) for a Distributed Environment  
> Folder: `Activity_API_for_Distributed_Environment`

---

## Q1: What command did you use to run the script?

```bash
python distributed_environment_api.py
```

**Video Evidence:**  
[`RUNNING_EVIDENCE_for_API-for-a-Distributed-Environment.mp4`](https://1drv.ms/v/c/2465e7dfd9d61c67/EbNqJPdEzpRJkwvWHkHH8V8BqS5YDeddW1W7cXXotxGpPA?e=5Hqq7Z) – Shows complete launch and terminal instructions printed by the script.

**Screenshot:**  
![`screenshots/run-result_distributed_environment_api.png`](./screenshots/run-result_distributed_environment_api.png)

---

## Q2: What happens when this command is run?
> 📌 **Note:** This activity uses Client URL `curl` for HyperText Transfer Protocol (HTTP) requests as it provides structured output, status codes, and JavaScript Object Notation (JSON) response formatting, ideal for testing APIs. Tools like `w3m` are meant for rendering HTML and are not suited for interacting with RESTful JSON APIs.

```bash
curl http://127.0.0.1:5000/user/Ann
```

### Output (PowerShell):
```plaintext

StatusCode        : 200
StatusDescription : OK
Content           : {
                        "name": "Ann",
                        "age": 32,
                        "occupation": "Doctor"
                    }

RawContent        : HTTP/1.1 200 OK
                    Connection: close
                    Content-Length: 65
                    Content-Type: application/json
                    Date: Sat, 19 Jul 2025 14:35:01 GMT
                    Server: Werkzeug/3.1.3 Python/3.12.5

                    {
                        "name": "Ann",
                        "age": 32,...
Forms             : {}
Headers           : {[Connection, close], [Content-Length, 65], [Content-Type, application/json], [Date, Sat, 19 Jul 2025 
                    14:35:01 GMT]...}
Images            : {}
InputFields       : {}
Links             : {}
ParsedHtml        : mshtml.HTMLDocumentClass
RawContentLength  : 65
```

**Explanation:**  
- The `GET` endpoint successfully finds a matching user in the `users` list.
- HTTP Status: `200 OK`  
- Clean JSON response.

**Screenshot:**  
![`screenshots/api_get_user_Ann.png`](./screenshots/api_get_user_Ann.png)

---

## Q3: What happens when querying a non-existent user?
> 📌 **Note:** This activity uses `curl` for HTTP requests as it provides structured output, status codes, and JSON response formatting, ideal for testing APIs. Tools like `w3m` are meant for rendering HTML and are not suited for interacting with RESTful JSON APIs.

```bash
curl http://127.0.0.1:5000/user/Adam
```

### Output (PowerShell):
```plaintext
curl : "User not found"
At line:1 char:1                                                                                                                   + curl http://127.0.0.1:5000/user/Adam                                                                                             + ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~                                                                                                 + CategoryInfo          : InvalidOperation: (System.Net.HttpWebRequest:HttpWebRequest) [Invoke-WebRequest], WebException       
    + FullyQualifiedErrorId : WebCmdletWebResponseException,Microsoft.PowerShell.Commands.InvokeWebRequestCommand
```

**Explanation:**  
- The user "Adam" is not in the predefined list.
- API responds with an error message.
- HTTP Status: `404 Not Found`

**Screenshot:**  
![`screenshots/api_get_user_Adam.png`](./screenshots/api_get_user_Adam.png)

---

## Q4: What does Flask enable in this project?

**Flask provides:**
- URL Routing (`/user/<string:name>`)
- Method-specific actions: `GET`, `POST`, `PUT`, `DELETE`
- Structured input parsing via `reqparse`
- JSON-based responses with status codes
- Local API server (development/testing)

Flask removes HTTP complexity and enables fast REST API creation with clean Python code.

---

**Structure Summary:**
| File | Purpose |
|------|---------|
| `distributed_environment_api.py` | Main Flask REST API script |
| `screenshots/` | Visual evidence of command outputs |
| [`RUNNING_EVIDENCE_for_API-for-a-Distributed-Environment.mp4`](https://1drv.ms/v/c/2465e7dfd9d61c67/EbNqJPdEzpRJkwvWHkHH8V8BqS5YDeddW1W7cXXotxGpPA?e=5Hqq7Z) | End-to-end video proof of execution |

---

All outputs and evidence conform to the requirements of Unit 7 activity.  
API tested with real `curl` commands and verified HTTP responses.

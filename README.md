# MemoryJSON.NET
Memory I/O Engine with JSON Files

```json
{
  "name": "Among Us",
  "description": "Trainer for Among Us",
  "processName": "Among Us",
  "trainers": [
    {
      "name": "Show Ghosts",
      "enabled": {
        "triggers": [
          {
            "function": "WriteMemory",
            "address": "GameAssembly.dll+20E7BB",
            "type": "bytes",
            "value": "80 7F 29 05 0F 85"
          }
        ]
      },
      "disabled": {
        "triggers": [
          {
            "function": "WriteMemory",
            "address": "GameAssembly.dll+20E7BB",
            "type": "bytes",
            "value": "80 7F 29 00 0F 84"
          }
        ]
      }
    }
  ]
}
```

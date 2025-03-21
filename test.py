import time

agent_commands = {
    # Preloaded for example purposes:
    "agent1": [{"cmd": "echo 'Hello from C2!'", "type": "shell", "timestamp": time.time()}],
    "agent2": [{"cmd": "whoami", "type": "shell", "timestamp": time.time()}],
}

command_data = agent_commands['agent1'].pop(0)
command_text = command_data.get("cmd")

print('data : ', command_data)
print('text : ', command_text)

command_data = agent_commands['agent1'].pop(0)
command_text = command_data.get("cmd")

print('data : ', command_data)
print('text : ', command_text)



"""
Data models for the C2 framework
"""
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

@dataclass
class Command:
    """Represents a command to be executed by an agent"""
    cmd: str
    type: str
    timestamp: float = field(default_factory=time.time)
    executed: bool = False
    result: Optional[Dict[str, Any]] = None
    
@dataclass
class Agent:
    """Represents a connected agent"""
    aid: str
    os_type: str
    arch: Optional[str] = None
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    token: Optional[str] = None
    client_nonce: Optional[str] = None
    server_nonce: Optional[str] = None
    verified: bool = False
    command_queue: List[Command] = field(default_factory=list)
    command_history: List[Dict[str, Any]] = field(default_factory=list)
    
class AgentManager:
    """Manages all connected agents"""
    def __init__(self):
        self.agents: Dict[str, Agent] = {}
        self.token_to_agent: Dict[str, str] = {}
        
    def register_agent(self, aid, os_type, arch=None):
        """Register a new agent or update an existing one"""
        if aid in self.agents:
            # Update existing agent
            agent = self.agents[aid]
            agent.last_seen = time.time()
            agent.os_type = os_type
            if arch:
                agent.arch = arch
        else:
            # Create new agent
            agent = Agent(aid=aid, os_type=os_type, arch=arch)
            self.agents[aid] = agent
        
        return agent
        
    def assign_token(self, aid, token):
        """Assign a token to an agent"""
        if aid not in self.agents:
            raise ValueError(f"Agent {aid} not registered")
            
        self.agents[aid].token = token
        self.token_to_agent[token] = aid
        
    def get_agent_by_token(self, token):
        """Get an agent by their token"""
        aid = self.token_to_agent.get(token)
        if not aid:
            return None
        return self.agents.get(aid)
        
    def get_agent(self, aid):
        """Get an agent by their ID"""
        return self.agents.get(aid)
        
    def add_command_to_queue(self, aid, command):
        """Add a command to an agent's queue"""
        if aid not in self.agents:
            raise ValueError(f"Agent {aid} not registered")
            
        self.agents[aid].command_queue.append(command)
        
    def get_next_command(self, aid):
        """Get the next command for an agent"""
        if aid not in self.agents:
            raise ValueError(f"Agent {aid} not registered")
            
        if not self.agents[aid].command_queue:
            return None
            
        return self.agents[aid].command_queue.pop(0)
        
    def record_command_result(self, aid, command, result):
        """Record the result of a command execution"""
        if aid not in self.agents:
            raise ValueError(f"Agent {aid} not registered")
            
        command.executed = True
        command.result = result
        self.agents[aid].command_history.append({
            "command": command.cmd,
            "type": command.type,
            "executed_at": time.time(),
            "result": result
        })
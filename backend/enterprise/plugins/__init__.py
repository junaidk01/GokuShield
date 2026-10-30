"""
Internal Plugin Architecture
=============================

Internal extensibility support for future v2 features.

NO public marketplace.
NO third-party SDK exposure.

Internal use only - future-proofing system architecture.
"""

from typing import Dict, Any, Optional, Callable
from abc import ABC, abstractmethod
import logging

logger = logging.getLogger(__name__)


class PluginInterface(ABC):
    """Base interface for internal plugins"""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Plugin name"""
        pass
    
    @property
    @abstractmethod
    def version(self) -> str:
        """Plugin version"""
        pass
    
    @abstractmethod
    def initialize(self, config: Dict[str, Any]) -> bool:
        """Initialize plugin with configuration"""
        pass
    
    @abstractmethod
    def execute(self, *args, **kwargs) -> Any:
        """Execute plugin functionality"""
        pass


class ServicePlugin(PluginInterface):
    """Base class for service enhancement plugins"""
    
    def __init__(self):
        self.enabled = False
        self.config = {}
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        """Initialize service plugin"""
        self.config = config
        self.enabled = True
        logger.info(f"Plugin {self.name} initialized")
        return True
    
    def shutdown(self):
        """Cleanup plugin resources"""
        self.enabled = False


class PluginRegistry:
    """
    Internal plugin registry.
    Manages plugin lifecycle and discovery.
    """
    
    def __init__(self):
        self.plugins: Dict[str, PluginInterface] = {}
        self.hooks: Dict[str, list] = {}
        
    def register(self, plugin: PluginInterface) -> bool:
        """Register plugin"""
        try:
            if plugin.name in self.plugins:
                logger.warning(f"Plugin {plugin.name} already registered")
                return False
                
            self.plugins[plugin.name] = plugin
            logger.info(f"Registered plugin: {plugin.name} v{plugin.version}")
            return True
            
        except Exception as e:
            logger.error(f"Plugin registration failed: {e}")
            return False
    
    def unregister(self, plugin_name: str) -> bool:
        """Unregister plugin"""
        if plugin_name in self.plugins:
            del self.plugins[plugin_name]
            logger.info(f"Unregistered plugin: {plugin_name}")
            return True
        return False
    
    def get_plugin(self, plugin_name: str) -> Optional[PluginInterface]:
        """Get plugin by name"""
        return self.plugins.get(plugin_name)
    
    def register_hook(self, hook_name: str, callback: Callable):
        """Register hook callback"""
        if hook_name not in self.hooks:
            self.hooks[hook_name] = []
        self.hooks[hook_name].append(callback)
        
    def execute_hook(self, hook_name: str, *args, **kwargs):
        """Execute all callbacks for a hook"""
        if hook_name in self.hooks:
            for callback in self.hooks[hook_name]:
                try:
                    callback(*args, **kwargs)
                except Exception as e:
                    logger.error(f"Hook execution failed: {e}")


# Global plugin registry
_plugin_registry = None


def get_plugin_registry() -> PluginRegistry:
    """Get global plugin registry"""
    global _plugin_registry
    if _plugin_registry is None:
        _plugin_registry = PluginRegistry()
    return _plugin_registry

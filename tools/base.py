from abc import ABC, abstractmethod

class BaseTool(ABC):
    name: str = ""
    category: str = ""
    description: str = ""

    @abstractmethod
    def run(self, cible):
        pass

    @abstractmethod
    def normalize(self, raw_output):
        pass

    def to_info(self) -> dict:
        return {
            "name": self.name,
            "category": self.category,
            "description": self.description
        }
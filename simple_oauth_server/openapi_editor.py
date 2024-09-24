import yaml
import json
from typing import Union, Dict

class OpenAPISpecParser:
    def __init__(self, spec: Union[Dict, str]):
        """
        Initialize the class by loading the OpenAPI specification.
        
        Args:
            spec (Union[Dict, str]): A dictionary containing the OpenAPI specification 
                                     or a string representing the file path (YAML or JSON).
        """
        if isinstance(spec, dict):
            self.openapi_spec = spec
        elif isinstance(spec, str):
            self.file_name = spec
            self.openapi_spec = self._load_openapi_spec()
        else:
            raise ValueError("The spec must be a dictionary or a file path as a string.")

    def _load_openapi_spec(self) -> Dict:
        """Load the OpenAPI spec from the provided YAML or JSON file."""
        with open(self.file_name, 'r') as file:
            if self.file_name.endswith('.yaml') or self.file_name.endswith('.yml'):
                return yaml.safe_load(file)
            elif self.file_name.endswith('.json'):
                return json.load(file)
            else:
                raise ValueError("Unsupported file format. Use .json, .yaml, or .yml.")

    def get_operation(self, path: str, method: str) -> Dict:
        """Retrieve a specific operation (method and path) from the OpenAPI spec."""
        method = method.lower()  # Ensure method is lowercase, as OpenAPI uses lowercase for methods
        
        # Check if the path exists in the spec
        if path not in self.openapi_spec.get('paths', {}):
            raise ValueError(f"Path '{path}' not found in OpenAPI spec.")
        
        # Check if the method exists for the specified path
        operations = self.openapi_spec['paths'][path]
        if method not in operations:
            raise ValueError(f"Method '{method}' not found for path '{path}' in OpenAPI spec.")
        
        # Return the operation details
        return operations[method]

    def add_operation_attribute(self, path: str, method: str, attribute: str, value) -> 'OpenAPISpecParser':
        """
        Add an attribute to a specific operation and return self for chaining.
        
        Args:
            path (str): The API path (e.g., "/token").
            method (str): The HTTP method (e.g., "post").
            attribute_name (str): The name of the attribute to add.
            attribute_value: The value of the attribute to add.
        
        Returns:
            OpenAPISpecParser: Returns the instance for chaining.
        """
        # Retrieve the operation
        operation = self.get_operation(path, method)
        
        # Add or update the attribute in the operation
        operation[attribute] = value
        
        # Return self to allow method chaining
        return self

    def to_yaml(self) -> str:
        """Return the OpenAPI specification as a YAML-formatted string."""
        return yaml.dump(self.openapi_spec, default_flow_style=False)

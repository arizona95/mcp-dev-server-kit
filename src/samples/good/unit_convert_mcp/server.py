from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

mcp = FastMCP("unit-convert")

TO_METER = {"mm": 0.001, "cm": 0.01, "m": 1.0, "km": 1000.0, "in": 0.0254, "ft": 0.3048}
TO_GRAM = {"g": 1.0, "kg": 1000.0, "lb": 453.59237, "oz": 28.349523125}


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def convert_length(value: float, from_unit: str, to_unit: str) -> float:
    """Convert a length between mm, cm, m, km, in, ft."""
    return value * TO_METER[from_unit] / TO_METER[to_unit]


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def convert_weight(value: float, from_unit: str, to_unit: str) -> float:
    """Convert a weight between g, kg, lb, oz."""
    return value * TO_GRAM[from_unit] / TO_GRAM[to_unit]


def main():
    mcp.run()


if __name__ == "__main__":
    main()

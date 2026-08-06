"""API testing tool specs."""

from .._spec import ToolSpec


TOOLS = {
    "postman":     ToolSpec(
            name="postman",
            binary="postman",
            description="API testing and development",
            params={"collection": None},
            timeout=300,
            builder=lambda p: ["postman", "run", p["collection"]],
        ),
    "insomnia":     ToolSpec(
            name="insomnia",
            binary="insomnia",
            description="API client",
            params={"collection": None},
            timeout=300,
            builder=lambda p: ["insomnia", "run", p["collection"]],
        ),
    "graphql_voyager":     ToolSpec(
            name="graphql_voyager",
            binary="graphql-voyager",
            description="GraphQL schema explorer",
            params={"url": None},
            timeout=30,
            builder=lambda p: ["graphql-voyager", p["url"]],
        ),
    "graphql_introspect":     ToolSpec(
            name="graphql_introspect",
            binary="graphql",
            description="GraphQL introspection",
            params={"url": None},
            timeout=30,
            builder=lambda p: ["graphql", "introspect", p["url"]],
        ),
    "arjun":     ToolSpec(
            name="arjun",
            binary="arjun",
            description="HTTP parameter discovery for web and API targets",
            params={"url": None, "method": "GET"},
            timeout=600,
            category="api",
            builder=lambda p: ["arjun", "-u", p["url"], "-m", p["method"]],
        ),
    "jwt_tool":     ToolSpec(
            name="jwt_tool",
            binary="jwt_tool",
            description="JWT testing toolkit",
            params={"token": None, "url": ""},
            timeout=300,
            builder=lambda p: ["jwt_tool", p["token"]] + (["-t", p["url"]] if p["url"] else []),
        ),
    "kiterunner":     ToolSpec(
            name="kiterunner",
            binary="kr",
            description="API endpoint discovery",
            params={"url": None, "wordlist": None},
            timeout=600,
            builder=lambda p: ["kr", "scan", p["url"], "-w", p["wordlist"]],
        ),
}

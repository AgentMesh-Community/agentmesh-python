"""Framework helpers. Each module needs its framework installed:

- ``agentmesh.integrations.langchain``: ``pip install agentmesh[langchain]``
- ``agentmesh.integrations.crewai``: ``pip install agentmesh[crewai]``

Frameworks that take plain Python functions (Google ADK, AutoGen, LlamaIndex)
use :meth:`agentmesh.tools.MeshTools.functions` directly.
"""

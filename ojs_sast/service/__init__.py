"""OJS-SAST service package.

The FastAPI app, queue, worker and storage live here and import their web
dependencies lazily (behind guards), so importing this package — or the pure
stdlib :mod:`ojs_sast.service.extract` module — never requires the optional
``service`` extra to be installed.
"""

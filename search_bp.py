from flask import Blueprint, redirect, request, url_for

# Blueprint für die /search-Route
search_bp = Blueprint("search_bp", __name__)

@search_bp.route("/search", endpoint="search")
def search():
    """Leitet alle Query-Parameter an die Index-Liste weiter.
    Dadurch funktionieren Form-Action="/search" in den Templates,
    auch wenn die eigentliche Ergebnisliste unter '/' gerendert wird.
    """
    return redirect(url_for("index", **request.args))

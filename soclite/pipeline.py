from .parser import parse_text
from .detector import detect, build_incidents

def ingest(store, text):
    """parse -> store -> detect over all events -> score -> incidents."""
    events, bad = parse_text(text)
    if events:
        store.add_events(events)
    alerts = detect(store.events())
    store.replace_alerts(alerts)
    store.upsert_incidents(build_incidents(alerts))
    return {"parsed": len(events), "bad_lines": bad, "alerts": len(alerts)}

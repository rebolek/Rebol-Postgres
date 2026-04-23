FROM postgres:17

# Default settings are fine; auth method is enforced via pg_hba at init (see workflow).
CMD ["postgres"]


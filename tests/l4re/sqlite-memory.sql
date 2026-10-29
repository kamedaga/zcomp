PRAGMA temp_store=MEMORY;
CREATE TABLE items(name TEXT, amount INTEGER);
BEGIN;
INSERT INTO items VALUES ('alpha', 10), ('beta', 20), ('gamma', 30);
UPDATE items SET amount=amount+5 WHERE name='beta';
COMMIT;
SELECT name, amount FROM items ORDER BY amount DESC;
SELECT count(*), sum(amount) FROM items;

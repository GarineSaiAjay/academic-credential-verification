-- Undoes 0002. Loses every stored external timestamp token (blocks stay, but are no longer anchored outside).
DROP TABLE block_timestamps;

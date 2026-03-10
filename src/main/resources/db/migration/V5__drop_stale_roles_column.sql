-- V5__drop_stale_roles_column.sql
-- users.roles TEXT[] was created in V1 but is never maintained by JPA.
-- Role data lives exclusively in the user_roles join table (@ElementCollection on User.roles).
ALTER TABLE users DROP COLUMN roles;

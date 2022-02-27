CREATE TABLE users
(
    id serial not null unique,
    username VARCHAR(255) not null unique,
    email VARCHAR(255),
    password_hash VARCHAR(255) not null,
    avatar_id int,
    role_id int not null
);

CREATE TABLE avatars
(
    id serial not null unique,
    name VARCHAR(48) not null,
    path text not null
);

CREATE TABLE roles
(
    id serial not null unique,
    name VARCHAR(48) not null,
    permission_id int not null
);

CREATE TABLE permissions
(
    id serial not null unique,
    can_read bool not null,
    can_write bool not null,
    can_access_private_data bool not null,
    can_manage_accounts bool not null
);

CREATE TABLE sessions
(
    id serial not null unique,
    user_id int references users (id) on delete cascade not null,
    refresh_token text not null,
    refresh_uuid text not null,
    issused_at int
);

CREATE TABLE sessions_history
(
    id int references sessions(id) on delete cascade not null,
    app_id int not null,
    ip_address text,
    city text,
    os text,
    time int not null
);

CREATE TABLE applications
(
    id serial not null unique,
    name VARCHAR(48) not null,
    type_id int not null,
    os text not null
);

CREATE TABLE application_types
(
    id serial not null unique,
    type text not null
);

CREATE TABLE settings
(
    id serial not null,
    user_id int references users(id) on delete cascade not null,
    data_encryption_enabled bool not null,
    cloud_notifications_enabled bool not null
);

-- default values

insert into roles(name, permission_id) values('user', 0);

insert into avatars(name, path) values ('NO AVATAR', '/');

insert into permissions(
    can_read, can_write, can_access_private_data, can_manage_accounts
) VALUES (
    true, true, false, false
);
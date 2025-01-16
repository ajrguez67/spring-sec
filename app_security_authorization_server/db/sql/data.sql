/*insert into users (username, password, enabled) VALUES
                                                    ('admin', 'to_be_encoded', true),
                                                    ('user', 'to_be_encoded', true);

insert into authorities (username, authority) VALUES
                                                  ('admin', 'admin'),
                                                  ('user', 'user');*/

/* insert into customers (email, pwd, rol)
VALUES ('super_user@debuggeandoieas.com', 'to_be_encoded', 'admin'),
       ('basic_user@debuggeandoieas.com', 'to_be_encoded', 'user');*/

insert into customers (email, pwd)
VALUES ('account@demo.com', '$2a$10$qO14CG4Hp4zkETu014j4S.f/68UUACGjxfhRQAA0bHTSvzGX2JlLC'),
       ('cards@demo.com', '$2a$10$qO14CG4Hp4zkETu014j4S.f/68UUACGjxfhRQAA0bHTSvzGX2JlLC'),
       ('loans@demo.com', '$2a$10$qO14CG4Hp4zkETu014j4S.f/68UUACGjxfhRQAA0bHTSvzGX2JlLC'),
       ('balance@demo.com', '$2a$10$qO14CG4Hp4zkETu014j4S.f/68UUACGjxfhRQAA0bHTSvzGX2JlLC');

/*insert into roles (role_name, description, id_customer)
VALUES ('VIEW_ACCOUNT','Can view account endpoints', 1),
       ('VIEW_CARDS','Can view cards endpoints', 2),
       ('VIEW_LOANS','Can view loans endpoints', 3),
       ('VIEW_BALANCE','Can view balance endpoints', 4);*/

-- Cambiando authorities por roles
insert into roles (role_name, description, id_customer)
VALUES ('ROLE_ADMIN','Can view account endpoints', 1),
       ('ROLE_ADMIN','Can view cards endpoints', 2),
       ('ROLE_USER','Can view loans endpoints', 3),
       ('ROLE_USER','Can view balance endpoints', 4);

insert into partners(
    client_id,
    client_name,
    client_secret,
    scopes,
    grant_types,
    authentication_methods,
    redirect_uri,
    redirect_uri_logout
)
values ('debuggeandoideas',
        'debuggeando ideas',
        '$2a$10$2Jd41/s0BLVajtJnRtDrGeI6X5RWj1J3k16zeAluKWWea5NURJRo2',
        'read,write',
        'authorization_code,refresh_token',
        'client_secret_basic,client_secret_jwt',
        'https://oauthdebugger.com/debug',
        'https://springone.io/authorized')
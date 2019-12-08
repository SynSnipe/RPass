create table app_user
(
	id integer
		constraint app_user_pk
			primary key autoincrement,
	username varchar,
	email varchar,
	phash varchar
);

create table stored_password
(
	id INTEGER not null
		primary key,
	userid int not null
		references app_user,
	username VARCHAR(120) not null,
	acctlocation VARCHAR(120),
	password VARCHAR(120)
);


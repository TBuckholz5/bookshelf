-- +goose Up
CREATE TABLE works (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    title                TEXT NOT NULL,
    subtitle             TEXT,
    description          TEXT,
    first_sentence       TEXT,
    notes                TEXT,
    first_publish_date   TEXT,
    cover_edition_id     UUID,

    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE authors (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    name            TEXT NOT NULL,
    eastern_order   BOOLEAN NOT NULL DEFAULT FALSE,
    personal_name   TEXT,
    enumeration     TEXT,
    title           TEXT,
    bio             TEXT,
    location        TEXT,
    birth_date      TEXT,
    death_date      TEXT,
    date            TEXT,
    wikipedia       TEXT,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE editions (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    title                  TEXT NOT NULL,
    title_prefix           TEXT,
    subtitle               TEXT,
    by_statement           TEXT,
    edition_name           TEXT,
    description            TEXT,
    notes                  TEXT,
    first_sentence         TEXT,
    publish_date           TEXT,
    copyright_date         TEXT,
    physical_dimensions    TEXT,
    physical_format        TEXT,
    number_of_pages        INTEGER,
    pagination             TEXT,
    weight                 TEXT,
    publish_country        TEXT,
    ocaid                  TEXT,
    translation_of         TEXT,
    accompanying_material  TEXT,
    scan_on_demand         BOOLEAN NOT NULL DEFAULT FALSE,

    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE editions_works (
    edition_id UUID REFERENCES editions(id) ON DELETE CASCADE,
    work_id    UUID REFERENCES works(id) ON DELETE CASCADE,
    PRIMARY KEY (edition_id, work_id)
);

CREATE TABLE works_authors (
    work_id   UUID REFERENCES works(id) ON DELETE CASCADE,
    author_id UUID REFERENCES authors(id) ON DELETE CASCADE,
    PRIMARY KEY (work_id, author_id)
);


-- +goose Down
DROP TABLE IF EXISTS works CASCADE;
DROP TABLE IF EXISTS authors CASCADE;
DROP TABLE IF EXISTS editions CASCADE;
DROP TABLE IF EXISTS editions_to_works_relation CASCADE;
DROP TABLE IF EXISTS works_to_authors_relation CASCADE;


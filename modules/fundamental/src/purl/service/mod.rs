use crate::{
    Error,
    purl::model::{
        details::{
            base_purl::BasePurlDetails, purl::PurlDetails, versioned_purl::VersionedPurlDetails,
        },
        summary::{base_purl::BasePurlSummary, purl::PurlSummary, r#type::TypeSummary},
    },
};
use sea_orm::{
    ColumnTrait, ColumnType, ConnectionTrait, EntityTrait, FromQueryResult, IntoIdentity,
    QueryFilter, QueryOrder, QuerySelect, prelude::Uuid,
};
use sea_query::{Expr, Func, Order, SimpleExpr};
use std::{collections::HashMap, fmt::Debug, str::FromStr};
use tracing::instrument;
use trustify_common::{
    db::{
        limiter::LimiterTrait,
        query::{Filtering, IntoColumns, Query},
    },
    model::{Paginated, PaginatedResults},
    purl::{Purl, PurlErr},
};
use trustify_entity::{
    base_purl,
    qualified_purl::{self, CanonicalPurl},
    versioned_purl,
};
use trustify_module_ingestor::{common::Deprecation, service::IngestorService};

#[derive(Default)]
pub struct PurlService {}

impl PurlService {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn purl_types<C: ConnectionTrait>(
        &self,
        connection: &C,
    ) -> Result<Vec<TypeSummary>, Error> {
        #[derive(FromQueryResult)]
        struct Ecosystem {
            r#type: String,
        }

        let ecosystems: Vec<_> = base_purl::Entity::find()
            .select_only()
            .column(base_purl::Column::Type)
            .group_by(base_purl::Column::Type)
            .distinct()
            .order_by(base_purl::Column::Type, Order::Asc)
            .into_model::<Ecosystem>()
            .all(connection)
            .await?
            .into_iter()
            .map(|e| e.r#type)
            .collect();

        TypeSummary::from_names(&ecosystems, connection).await
    }

    pub async fn base_purls_by_type<C: ConnectionTrait>(
        &self,
        r#type: &str,
        query: Query,
        paginated: Paginated,
        connection: &C,
    ) -> Result<PaginatedResults<BasePurlSummary>, Error> {
        let limiter = base_purl::Entity::find()
            .filter(base_purl::Column::Type.eq(r#type))
            .filtering(query)?
            .limiting(connection, paginated.offset, paginated.limit);

        let total = limiter.total().await?;

        Ok(PaginatedResults {
            items: BasePurlSummary::from_entities(&limiter.fetch().await?).await?,
            total,
        })
    }

    pub async fn base_purl<C: ConnectionTrait>(
        &self,
        r#type: &str,
        namespace: Option<String>,
        name: &str,
        connection: &C,
    ) -> Result<Option<BasePurlDetails>, Error> {
        let mut query = base_purl::Entity::find()
            .filter(base_purl::Column::Type.eq(r#type))
            .filter(base_purl::Column::Name.eq(name));

        if let Some(ns) = namespace {
            query = query.filter(base_purl::Column::Namespace.eq(ns));
        } else {
            query = query.filter(base_purl::Column::Namespace.is_null());
        }

        if let Some(package) = query.one(connection).await? {
            Ok(Some(
                BasePurlDetails::from_entity(&package, connection).await?,
            ))
        } else {
            Ok(None)
        }
    }

    pub async fn versioned_purl<C: ConnectionTrait>(
        &self,
        r#type: &str,
        namespace: Option<String>,
        name: &str,
        version: &str,
        connection: &C,
    ) -> Result<Option<VersionedPurlDetails>, Error> {
        let mut query = versioned_purl::Entity::find()
            .left_join(base_purl::Entity)
            .filter(base_purl::Column::Type.eq(r#type))
            .filter(base_purl::Column::Name.eq(name))
            .filter(versioned_purl::Column::Version.eq(version));

        if let Some(ns) = namespace {
            query = query.filter(base_purl::Column::Namespace.eq(ns));
        } else {
            query = query.filter(base_purl::Column::Namespace.is_null());
        }

        let package_version = query.one(connection).await?;

        if let Some(package_version) = package_version {
            Ok(Some(
                VersionedPurlDetails::from_entity(None, &package_version, connection).await?,
            ))
        } else {
            Ok(None)
        }
    }

    pub async fn base_purl_by_uuid<C: ConnectionTrait>(
        &self,
        base_purl_uuid: &Uuid,
        connection: &C,
    ) -> Result<Option<BasePurlDetails>, Error> {
        if let Some(package) = base_purl::Entity::find_by_id(*base_purl_uuid)
            .one(connection)
            .await?
        {
            Ok(Some(
                BasePurlDetails::from_entity(&package, connection).await?,
            ))
        } else {
            Ok(None)
        }
    }

    pub async fn base_purl_by_purl<C: ConnectionTrait>(
        &self,
        purl: &Purl,
        connection: &C,
    ) -> Result<Option<BasePurlDetails>, Error> {
        let mut query = base_purl::Entity::find()
            .filter(base_purl::Column::Type.eq(&purl.ty))
            .filter(base_purl::Column::Name.eq(&purl.name));

        if let Some(ns) = &purl.namespace {
            query = query.filter(base_purl::Column::Namespace.eq(ns));
        } else {
            query = query.filter(base_purl::Column::Namespace.is_null());
        }

        if let Some(base_purl) = query.one(connection).await? {
            Ok(Some(
                BasePurlDetails::from_entity(&base_purl, connection).await?,
            ))
        } else {
            Ok(None)
        }
    }

    pub async fn versioned_purl_by_uuid<C: ConnectionTrait>(
        &self,
        purl_version_uuid: &Uuid,
        connection: &C,
    ) -> Result<Option<VersionedPurlDetails>, Error> {
        if let Some(package_version) = versioned_purl::Entity::find_by_id(*purl_version_uuid)
            .one(connection)
            .await?
        {
            Ok(Some(
                VersionedPurlDetails::from_entity(None, &package_version, connection).await?,
            ))
        } else {
            Ok(None)
        }
    }

    pub async fn versioned_purl_by_purl<C: ConnectionTrait>(
        &self,
        purl: &Purl,
        connection: &C,
    ) -> Result<Option<VersionedPurlDetails>, Error> {
        if let Some(version) = &purl.version {
            let mut query = versioned_purl::Entity::find()
                .left_join(base_purl::Entity)
                .filter(base_purl::Column::Type.eq(&purl.ty))
                .filter(base_purl::Column::Name.eq(&purl.name))
                .filter(versioned_purl::Column::Version.eq(version));

            if let Some(ns) = &purl.namespace {
                query = query.filter(base_purl::Column::Namespace.eq(ns));
            } else {
                query = query.filter(base_purl::Column::Namespace.is_null());
            }

            let package_version = query.one(connection).await?;

            if let Some(package_version) = package_version {
                Ok(Some(
                    VersionedPurlDetails::from_entity(None, &package_version, connection).await?,
                ))
            } else {
                Ok(None)
            }
        } else {
            Err(Error::Purl(PurlErr::MissingVersion(
                "A versioned pURL requires a version".to_string(),
            )))
        }
    }

    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
    pub async fn fetch_purl_details<C: ConnectionTrait, I: AsRef<str> + Debug>(
        &self,
        identifiers: &[I],
        deprecated: Deprecation,
        connection: &C,
        ingestor: Option<&IngestorService>,
    ) -> Result<HashMap<String, PurlDetails>, Error> {
        let (purls, uuids): (Vec<_>, Vec<_>) = identifiers
            .iter()
            .partition(|key| key.as_ref().starts_with("pkg:"));

        let purls: Vec<_> = purls
            .iter()
            .map(|k| Purl::from_str(k.as_ref()).map_err(Error::Purl))
            .collect::<Result<_, _>>()?;

        let uuids: Vec<_> = uuids
            .iter()
            .map(|k| Uuid::from_str(k.as_ref()).map_err(Error::Uuid))
            .collect::<Result<_, _>>()?;

        let details = self
            .purls_by_purl(&purls, deprecated, connection, ingestor)
            .await?
            .into_iter()
            .map(|detail| (detail.head.purl.to_string(), detail))
            .chain(
                self.purls_by_uuid(&uuids, deprecated, connection)
                    .await?
                    .into_iter()
                    .map(|detail| (detail.head.uuid.to_string(), detail)),
            )
            .collect();

        Ok(details)
    }

    async fn ingest_missing_purls<C: ConnectionTrait>(
        &self,
        purls: &[Purl],
        connection: &C,
        ingestor: &IngestorService,
    ) {
        let ingestion_futures: Vec<_> = purls
            .iter()
            .map(|purl| {
                // Clone the package URL if needed (depending on its type).
                let purl = purl.clone();
                async move {
                    match ingestor
                        .graph()
                        .get_qualified_package(&purl, connection)
                        .await
                    {
                        Ok(Some(_)) => (), // Package exists, do nothing.
                        Ok(None) => {
                            if let Err(e) = ingestor
                                .graph()
                                .ingest_qualified_package(&purl, connection)
                                .await
                            {
                                log::error!("Failed to ingest package {}: {:?}", purl, e);
                            }
                        }
                        Err(e) => log::error!("Failed to check package {}: {:?}", purl, e),
                    }
                }
            })
            .collect();

        futures_util::future::join_all(ingestion_futures).await;
    }

    async fn purls_by_purl<C: ConnectionTrait>(
        &self,
        purls: &[Purl],
        deprecation: Deprecation,
        connection: &C,
        ingestor: Option<&IngestorService>,
    ) -> Result<Vec<PurlDetails>, Error> {
        if purls.is_empty() {
            return Ok(Default::default());
        }
        if let Some(ingestor_svc) = ingestor {
            self.ingest_missing_purls(purls, connection, ingestor_svc)
                .await;
        }

        let canonical: Vec<CanonicalPurl> = purls
            .iter()
            .map(|purl| CanonicalPurl::from(purl.clone()))
            .collect();

        let items = qualified_purl::Entity::find()
            .filter(qualified_purl::Column::Purl.is_in(canonical))
            .all(connection)
            .await?;

        let mut details = Vec::with_capacity(items.len());
        for purl in items {
            details
                .push(PurlDetails::from_entity(None, None, &purl, deprecation, connection).await?);
        }
        Ok(details)
    }

    async fn purls_by_uuid<C: ConnectionTrait>(
        &self,
        uuids: &[Uuid],
        deprecation: Deprecation,
        connection: &C,
    ) -> Result<Vec<PurlDetails>, Error> {
        if uuids.is_empty() {
            return Ok(Default::default());
        }
        let items = qualified_purl::Entity::find()
            .filter(qualified_purl::Column::Id.is_in(uuids.to_vec()))
            .all(connection)
            .await?;

        let mut details = Vec::with_capacity(items.len());
        for purl in items {
            details
                .push(PurlDetails::from_entity(None, None, &purl, deprecation, connection).await?);
        }
        Ok(details)
    }

    pub async fn base_purls<C: ConnectionTrait>(
        &self,
        query: Query,
        paginated: Paginated,
        connection: &C,
    ) -> Result<PaginatedResults<BasePurlSummary>, Error> {
        let limiter = base_purl::Entity::find().filtering(query)?.limiting(
            connection,
            paginated.offset,
            paginated.limit,
        );

        let total = limiter.total().await?;

        Ok(PaginatedResults {
            items: BasePurlSummary::from_entities(&limiter.fetch().await?).await?,
            total,
        })
    }

    #[instrument(skip(self, connection), err)]
    pub async fn purls<C: ConnectionTrait>(
        &self,
        query: Query,
        paginated: Paginated,
        connection: &C,
    ) -> Result<PaginatedResults<PurlSummary>, Error> {
        let limiter = qualified_purl::Entity::find()
            .filtering_with(
                query,
                qualified_purl::Entity
                    .columns()
                    .json_keys("purl", &["ty", "namespace", "name", "version"])
                    .json_keys("qualifiers", &["arch", "distro", "repository_url"])
                    .translator(|f, op, v| match f {
                        "type" => Some(format!("ty{op}{v}")),
                        _ => None,
                    })
                    .add_expr(
                        "purl",
                        SimpleExpr::FunctionCall(
                            Func::cust("get_purl".into_identity())
                                .arg(Expr::col(qualified_purl::Column::Id)),
                        ),
                        ColumnType::Text,
                    ),
            )?
            .limiting(connection, paginated.offset, paginated.limit);

        let total = limiter.total().await?;

        Ok(PaginatedResults {
            items: PurlSummary::from_entities(&limiter.fetch().await?),
            total,
        })
    }

    #[instrument(skip(self, connection), err)]
    pub async fn gc_purls<C: ConnectionTrait>(&self, connection: &C) -> Result<u64, Error> {
        let res = connection
            .execute_unprepared(include_str!("gc_purls.sql"))
            .await?;

        Ok(res.rows_affected())
    }
}

#[cfg(test)]
mod test;

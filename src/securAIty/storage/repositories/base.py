"""
Base Repository

Generic repository pattern implementation with async CRUD operations.
"""

from typing import Any, Generic, Optional, Type, TypeVar, List, Dict, Callable
from datetime import datetime, timezone

from sqlalchemy import Select, func, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from securAIty.storage.models.base import Base

ModelType = TypeVar("ModelType", bound=Base)


class BaseRepository(Generic[ModelType]):
    """
    Base repository with generic CRUD operations.

    Provides fundamental database operations for all entities.

    Attributes:
        model: SQLAlchemy model class
        session: Async database session
    """

    def __init__(self, session: AsyncSession, model: Type[ModelType]) -> None:
        """
        Initialize repository.

        Args:
            session: Async SQLAlchemy session
            model: SQLAlchemy model class
        """
        self.session = session
        self.model = model

    async def get_by_id(self, id_value: int) -> Optional[ModelType]:
        """
        Get entity by primary key.

        Args:
            id_value: Primary key value

        Returns:
            Entity or None if not found
        """
        result = await self.session.get(self.model, id_value)
        return result

    async def get_by_ids(self, id_values: List[int]) -> List[ModelType]:
        """
        Get multiple entities by primary keys.

        Args:
            id_values: List of primary key values

        Returns:
            List of entities
        """
        from sqlalchemy import select
        stmt = select(self.model).where(self.model.__table__.primary_key.columns[0].in_(id_values))
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_all(
        self,
        skip: int = 0,
        limit: int = 100,
        order_by: Optional[Callable[[ModelType], Any]] = None,
    ) -> List[ModelType]:
        """
        Get all entities with pagination.

        Args:
            skip: Number of records to skip
            limit: Maximum number of records
            order_by: Optional ordering function

        Returns:
            List of entities
        """
        from sqlalchemy import select
        stmt = select(self.model)
        
        if order_by:
            stmt = stmt.order_by(order_by(self.model))
        
        stmt = stmt.offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_by_filter(
        self,
        filters: Dict[str, Any],
        skip: int = 0,
        limit: int = 100,
    ) -> List[ModelType]:
        """
        Get entities by filter criteria.

        Args:
            filters: Dictionary of column-value filters
            skip: Number of records to skip
            limit: Maximum number of records

        Returns:
            List of matching entities
        """
        from sqlalchemy import select
        conditions = [getattr(self.model, key) == value for key, value in filters.items()]
        stmt = select(self.model).where(and_(*conditions))
        stmt = stmt.offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_first(self, filters: Optional[Dict[str, Any]] = None) -> Optional[ModelType]:
        """
        Get first entity matching filters.

        Args:
            filters: Optional filter criteria

        Returns:
            First matching entity or None
        """
        from sqlalchemy import select
        stmt = select(self.model)
        
        if filters:
            conditions = [getattr(self.model, key) == value for key, value in filters.items()]
            stmt = stmt.where(and_(*conditions))
        
        stmt = stmt.limit(1)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def create(
        self,
        attributes: Dict[str, Any],
        commit: bool = True,
    ) -> ModelType:
        """
        Create new entity.

        Args:
            attributes: Entity attributes
            commit: Whether to commit transaction

        Returns:
            Created entity
        """
        entity = self.model(**attributes)
        self.session.add(entity)
        
        if commit:
            await self.session.commit()
            await self.session.refresh(entity)
        
        return entity

    async def create_many(
        self,
        attributes_list: List[Dict[str, Any]],
        commit: bool = True,
    ) -> List[ModelType]:
        """
        Create multiple entities.

        Args:
            attributes_list: List of entity attributes
            commit: Whether to commit transaction

        Returns:
            List of created entities
        """
        entities = [self.model(**attrs) for attrs in attributes_list]
        self.session.add_all(entities)
        
        if commit:
            await self.session.commit()
            for entity in entities:
                await self.session.refresh(entity)
        
        return entities

    async def update(
        self,
        id_value: int,
        attributes: Dict[str, Any],
        commit: bool = True,
    ) -> Optional[ModelType]:
        """
        Update entity by primary key.

        Args:
            id_value: Primary key value
            attributes: Attributes to update
            commit: Whether to commit transaction

        Returns:
            Updated entity or None if not found
        """
        entity = await self.get_by_id(id_value)
        
        if entity is None:
            return None
        
        for key, value in attributes.items():
            setattr(entity, key, value)
        
        if commit:
            await self.session.commit()
            await self.session.refresh(entity)
        
        return entity

    async def update_by_filter(
        self,
        filters: Dict[str, Any],
        attributes: Dict[str, Any],
        commit: bool = True,
    ) -> int:
        """
        Update entities matching filters.

        Args:
            filters: Filter criteria
            attributes: Attributes to update
            commit: Whether to commit transaction

        Returns:
            Number of updated entities
        """
        from sqlalchemy import update
        conditions = [getattr(self.model, key) == value for key, value in filters.items()]
        stmt = update(self.model).where(and_(*conditions)).values(**attributes)
        result = await self.session.execute(stmt)
        
        if commit:
            await self.session.commit()
        
        return result.rowcount or 0

    async def delete(
        self,
        id_value: int,
        commit: bool = True,
    ) -> bool:
        """
        Delete entity by primary key.

        Args:
            id_value: Primary key value
            commit: Whether to commit transaction

        Returns:
            True if deleted, False if not found
        """
        entity = await self.get_by_id(id_value)
        
        if entity is None:
            return False
        
        await self.session.delete(entity)
        
        if commit:
            await self.session.commit()
        
        return True

    async def delete_by_filter(
        self,
        filters: Dict[str, Any],
        commit: bool = True,
    ) -> int:
        """
        Delete entities matching filters.

        Args:
            filters: Filter criteria
            commit: Whether to commit transaction

        Returns:
            Number of deleted entities
        """
        from sqlalchemy import delete
        conditions = [getattr(self.model, key) == value for key, value in filters.items()]
        stmt = delete(self.model).where(and_(*conditions))
        result = await self.session.execute(stmt)
        
        if commit:
            await self.session.commit()
        
        return result.rowcount or 0

    async def exists(self, filters: Dict[str, Any]) -> bool:
        """
        Check if entity exists matching filters.

        Args:
            filters: Filter criteria

        Returns:
            True if exists, False otherwise
        """
        from sqlalchemy import select
        stmt = select(func.count()).select_from(self.model)
        
        if filters:
            conditions = [getattr(self.model, key) == value for key, value in filters.items()]
            stmt = stmt.where(and_(*conditions))
        
        result = await self.session.execute(stmt)
        count = result.scalar()
        return count > 0

    async def count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        """
        Count entities matching filters.

        Args:
            filters: Optional filter criteria

        Returns:
            Number of matching entities
        """
        from sqlalchemy import select
        stmt = select(func.count()).select_from(self.model)
        
        if filters:
            conditions = [getattr(self.model, key) == value for key, value in filters.items()]
            stmt = stmt.where(and_(*conditions))
        
        result = await self.session.execute(stmt)
        return result.scalar() or 0

    async def search(
        self,
        query: str,
        search_columns: List[str],
        skip: int = 0,
        limit: int = 100,
    ) -> List[ModelType]:
        """
        Search entities by text query.

        Args:
            query: Search query string
            search_columns: Columns to search
            skip: Number of records to skip
            limit: Maximum number of records

        Returns:
            List of matching entities
        """
        from sqlalchemy import select
        conditions = [
            getattr(self.model, column).ilike(f"%{query}%")
            for column in search_columns
            if hasattr(self.model, column)
        ]
        
        if not conditions:
            return []
        
        stmt = select(self.model).where(or_(*conditions))
        stmt = stmt.offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def upsert(
        self,
        unique_field: str,
        unique_value: Any,
        attributes: Dict[str, Any],
        commit: bool = True,
    ) -> ModelType:
        """
        Upsert entity by unique field.

        Args:
            unique_field: Unique field name
            unique_value: Unique field value
            attributes: Entity attributes
            commit: Whether to commit transaction

        Returns:
            Created or updated entity
        """
        from sqlalchemy import select, update
        
        filters = {unique_field: unique_value}
        entity = await self.get_first(filters)
        
        if entity:
            for key, value in attributes.items():
                setattr(entity, key, value)
            if commit:
                await self.session.commit()
                await self.session.refresh(entity)
        else:
            entity = self.model(**attributes)
            self.session.add(entity)
            if commit:
                await self.session.commit()
                await self.session.refresh(entity)
        
        return entity

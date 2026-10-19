use std::ffi::c_void;

/// Wrapper around [`tokio::runtime::Runtime`] that can be safely passed across the FFI boundary.
#[repr(C)]
pub struct Runtime {
    inner: Pointer<tokio::runtime::Runtime>,
}

impl Runtime {
    /// Creates a new owned [`Runtime`] instance.
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let inner = tokio::runtime::Runtime::new()?;
        Ok(Self {
            inner: Pointer::owned(inner),
        })
    }

    /// Creates a new owned [`Runtime`] instance from an existing [`tokio::runtime::Runtime`].
    pub fn from_owned(inner: tokio::runtime::Runtime) -> Self {
        Self {
            inner: Pointer::owned(inner),
        }
    }

    /// Creates a new borrowed [`Runtime`] instance from a reference to an existing
    /// `tokio::runtime::Runtime`.
    ///
    /// # Safety
    /// The caller must ensure that the provided reference remains valid for the lifetime of the
    /// returned [`Runtime`].
    pub const unsafe fn from_borrowed(inner: &tokio::runtime::Runtime) -> Self {
        Self {
            // SAFETY: The caller must ensure the validness of the `inner` reference.
            inner: unsafe { Pointer::borrowed(inner) },
        }
    }
}

impl AsRef<tokio::runtime::Runtime> for Runtime {
    fn as_ref(&self) -> &tokio::runtime::Runtime {
        self.inner
            .as_ref()
            .expect("Runtime pointer should not be null")
    }
}

impl std::ops::Deref for Runtime {
    type Target = tokio::runtime::Runtime;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

#[repr(C)]
struct Pointer<T> {
    kind: PointerKind,
    _marker: std::marker::PhantomData<T>,
}

#[repr(C)]
enum PointerKind {
    Owned(*mut c_void),
    Borrowed(*const c_void),
    Null,
}

impl<T> Pointer<T> {
    /// Creates a new owned pointer from a value.
    pub fn owned(value: T) -> Self {
        let boxed = Box::new(value);
        let kind = PointerKind::Owned(Box::into_raw(boxed).cast::<c_void>());
        Self {
            kind,
            _marker: std::marker::PhantomData,
        }
    }

    /// Creates a new borrowed pointer from a reference to an existing value.
    ///
    /// # Safety
    /// The caller must ensure that the provided reference remains valid for the lifetime of the
    /// returned pointer.
    pub const unsafe fn borrowed(value: &T) -> Self {
        let kind = PointerKind::Borrowed(std::ptr::from_ref(value).cast::<c_void>());
        Self {
            kind,
            _marker: std::marker::PhantomData,
        }
    }

    /// Returns a reference to the value if the pointer is owned or borrowed, or [`None`] if it is
    /// null.
    pub const fn as_ref(&self) -> Option<&T> {
        match self.kind {
            PointerKind::Owned(ptr) => unsafe { (ptr.cast::<T>()).as_ref() },
            PointerKind::Borrowed(ptr) => unsafe { (ptr.cast::<T>()).as_ref() },
            PointerKind::Null => None,
        }
    }

    /// Takes ownership of the pointer if it is owned, returning the raw pointer and leaving a null
    /// pointer in its place.
    /// If the pointer is borrowed or null, returns [`None`].
    #[expect(dead_code, reason = "May be useful in future")]
    pub fn take(&mut self) -> Option<T> {
        match std::mem::replace(&mut self.kind, PointerKind::Null) {
            PointerKind::Owned(ptr) => {
                // SAFETY: We ensure that the pointer is valid and was allocated by us.
                let boxed = unsafe { Box::from_raw(ptr.cast::<T>()) };
                Some(*boxed)
            }
            PointerKind::Borrowed(_) | PointerKind::Null => None,
        }
    }
}

impl<T> Drop for Pointer<T> {
    fn drop(&mut self) {
        let Self { kind, _marker } = self;

        if let PointerKind::Owned(ptr) = *kind {
            // SAFETY: We ensure that the pointer is valid and was allocated by us.
            unsafe {
                drop(Box::from_raw(ptr.cast::<T>()));
            }
        }
    }
}

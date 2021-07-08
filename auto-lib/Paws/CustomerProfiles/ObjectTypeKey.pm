# Generated by default/object.tt
package Paws::CustomerProfiles::ObjectTypeKey;
  use Moose;
  has FieldNames => (is => 'ro', isa => 'ArrayRef[Str|Undef]');
  has StandardIdentifiers => (is => 'ro', isa => 'ArrayRef[Str|Undef]');

1;

### main pod documentation begin ###

=head1 NAME

Paws::CustomerProfiles::ObjectTypeKey

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::CustomerProfiles::ObjectTypeKey object:

  $service_obj->Method(Att1 => { FieldNames => $value, ..., StandardIdentifiers => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::CustomerProfiles::ObjectTypeKey object:

  $result = $service_obj->Method(...);
  $result->Att1->FieldNames

=head1 DESCRIPTION

An object that defines the Key element of a ProfileObject. A Key is a
special element that can be used to search for a customer profile.

=head1 ATTRIBUTES


=head2 FieldNames => ArrayRef[Str|Undef]

The reference for the key name of the fields map.


=head2 StandardIdentifiers => ArrayRef[Str|Undef]

The types of keys that a ProfileObject can have. Each ProfileObject can
have only 1 UNIQUE key but multiple PROFILE keys. PROFILE means that
this key can be used to tie an object to a PROFILE. UNIQUE means that
it can be used to uniquely identify an object. If a key a is marked as
SECONDARY, it will be used to search for profiles after all other
PROFILE keys have been searched. A LOOKUP_ONLY key is only used to
match a profile but is not persisted to be used for searching of the
profile. A NEW_ONLY key is only used if the profile does not already
exist before the object is ingested, otherwise it is only used for
matching objects to profiles.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::CustomerProfiles>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut


# Generated by default/object.tt
package Paws::CustomerProfiles::ListIntegrationItem;
  use Moose;
  has CreatedAt => (is => 'ro', isa => 'Str', required => 1);
  has DomainName => (is => 'ro', isa => 'Str', required => 1);
  has LastUpdatedAt => (is => 'ro', isa => 'Str', required => 1);
  has ObjectTypeName => (is => 'ro', isa => 'Str', required => 1);
  has Tags => (is => 'ro', isa => 'Paws::CustomerProfiles::TagMap');
  has Uri => (is => 'ro', isa => 'Str', required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::CustomerProfiles::ListIntegrationItem

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::CustomerProfiles::ListIntegrationItem object:

  $service_obj->Method(Att1 => { CreatedAt => $value, ..., Uri => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::CustomerProfiles::ListIntegrationItem object:

  $result = $service_obj->Method(...);
  $result->Att1->CreatedAt

=head1 DESCRIPTION

An integration in list of integrations.

=head1 ATTRIBUTES


=head2 B<REQUIRED> CreatedAt => Str

The timestamp of when the domain was created.


=head2 B<REQUIRED> DomainName => Str

The unique name of the domain.


=head2 B<REQUIRED> LastUpdatedAt => Str

The timestamp of when the domain was most recently edited.


=head2 B<REQUIRED> ObjectTypeName => Str

The name of the profile object type.


=head2 Tags => L<Paws::CustomerProfiles::TagMap>

The tags used to organize, track, or control access for this resource.


=head2 B<REQUIRED> Uri => Str

The URI of the S3 bucket or any other type of data source.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::CustomerProfiles>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

